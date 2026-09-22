"""分叉裁决 (fork resolution) 接口与校验语义的端到端测试。"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import crypto  # noqa: E402
from app.config import Settings  # noqa: E402
from app.database import init_db  # noqa: E402
from app.main import app, db  # noqa: E402


@pytest.fixture()
def client():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)

    def _db():
        yield conn

    app.dependency_overrides[db] = _db
    cfg = Settings(
        database_path=":memory:",
        trusted_root_issuers=frozenset(),
        max_chain_depth=256,
    )
    import app.main as main_mod

    main_mod.settings = cfg
    try:
        with TestClient(app) as c:
            yield c, conn
    finally:
        app.dependency_overrides.clear()


def _keypair():
    priv = Ed25519PrivateKey.generate()
    return priv, crypto.encode_public_key(priv.public_key())


def _post_proof(client, priv, pub, artifact, parent=None, signature=None):
    sig = signature if signature is not None else crypto.sign(priv, artifact, parent)
    return client.post(
        "/proofs",
        json={
            "artifact_digest": artifact,
            "issuer": pub,
            "parent_digest": parent,
            "signature": sig,
        },
    )


def _resolve(client, artifact, proof_id, reason="人工裁决: 采用 A 签发者分支"):
    return client.post(
        "/fork-resolutions",
        json={
            "artifact_digest": artifact,
            "selected_proof_id": proof_id,
            "reason": reason,
        },
    )


def _set_created_at(conn, artifact, ts, issuer=None):
    sql = "UPDATE proofs SET created_at = ? WHERE artifact_digest = ?"
    params: list = [ts, artifact]
    if issuer is not None:
        sql += " AND issuer = ?"
        params.append(issuer)
    conn.execute(sql, params)
    conn.commit()


def _set_resolved_at(conn, artifact, ts, resolution_id=None):
    sql = "UPDATE fork_resolutions SET resolved_at = ? WHERE artifact_digest = ?"
    params: list = [ts, artifact]
    if resolution_id is not None:
        sql += " AND id = ?"
        params.append(resolution_id)
    conn.execute(sql, params)
    conn.commit()


# ---------- POST /fork-resolutions 合法性 ----------


def test_resolution_requires_fork_409(client):
    c, _ = client
    priv, pub = _keypair()
    r = _post_proof(c, priv, pub, "sha256:single")
    # 只有一条证明 -> 无分叉
    res = _resolve(c, "sha256:single", r.json()["proof_id"])
    assert res.status_code == 409
    assert "分叉" in res.json()["detail"]

    # 制品完全不存在同样 409
    res = _resolve(c, "sha256:missing", 999)
    assert res.status_code == 409


def test_resolution_selected_id_must_belong_to_target_400(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    r1 = _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")

    # 自增 id 尚未被使用 -> 不属于目标
    res = _resolve(c, "sha256:child", r1.json()["proof_id"] + 100)
    assert res.status_code == 400

    # 用另一制品的 proof_id 裁决本制品
    other = _post_proof(c, k1, p1, "sha256:other")
    res = _resolve(c, "sha256:child", other.json()["proof_id"])
    assert res.status_code == 400


def test_resolution_created_with_full_branch_snapshot(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    r1 = _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    r2 = _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")

    res = _resolve(c, "sha256:child", r1.json()["proof_id"])
    assert res.status_code == 201
    body = res.json()
    assert body["status"] == "RESOLVED"
    assert body["artifact_digest"] == "sha256:child"
    assert body["selected_proof_id"] == r1.json()["proof_id"]
    assert body["reason"]
    # 原子固化了裁决当时的全部分支 proof_id
    assert sorted(body["branch_proof_ids"]) == sorted(
        [r1.json()["proof_id"], r2.json()["proof_id"]]
    )
    assert body["resolved_at"]
    assert isinstance(body["id"], int)


def test_resolutions_are_append_only(client):
    c, conn = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    r1 = _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    r2 = _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")

    a = _resolve(c, "sha256:child", r1.json()["proof_id"], reason="第一次裁决")
    b = _resolve(c, "sha256:child", r2.json()["proof_id"], reason="第二次裁决")
    assert a.status_code == 201 and b.status_code == 201
    # 追加: 新 id、新理由、新时间, 旧记录保留
    assert b.json()["id"] > a.json()["id"]
    assert b.json()["selected_proof_id"] == r2.json()["proof_id"]
    assert conn.execute(
        "SELECT COUNT(*) AS n FROM fork_resolutions"
    ).fetchone()["n"] == 2


def test_resolution_bad_payload_4xx(client):
    c, _ = client
    # 缺 selected_proof_id
    res = c.post(
        "/fork-resolutions",
        json={"artifact_digest": "sha256:x", "reason": "r"},
    )
    assert res.status_code == 422
    # selected_proof_id 非正整数
    res = c.post(
        "/fork-resolutions",
        json={"artifact_digest": "sha256:x", "selected_proof_id": 0, "reason": "r"},
    )
    assert res.status_code == 422
    # reason 为空串
    res = c.post(
        "/fork-resolutions",
        json={"artifact_digest": "sha256:x", "selected_proof_id": 1, "reason": ""},
    )
    assert res.status_code == 422


# ---------- 实时校验: 裁决消解分叉 ----------


def test_verify_fork_before_resolution_still_fork(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")

    body = c.get("/verify/sha256:child").json()
    assert body["status"] == "FORK"
    assert "applied_resolution" not in body


def test_verify_target_fork_resolved_continues_chain(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    r1 = _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")

    res = _resolve(c, "sha256:child", r1.json()["proof_id"])
    body = c.get("/verify/sha256:child").json()
    assert body["status"] == "OK"
    assert body["length"] == 2
    assert [e["artifact_digest"] for e in body["chain"]] == [
        "sha256:child",
        "sha256:root",
    ]
    # 选定的是 k1 的分支 (issuer == p1)
    assert body["chain"][0]["issuer"] == p1
    assert body["chain"][0]["resolution"]["id"] == res.json()["id"]
    assert body["applied_resolution"]["selected_proof_id"] == r1.json()["proof_id"]
    assert set(body["applied_resolution"]["branch_proof_ids"]) == set(
        res.json()["branch_proof_ids"]
    )


def test_verify_ancestor_fork_resolved(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    m1 = _post_proof(c, k1, p1, "sha256:mid", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:mid", parent="sha256:root")
    _post_proof(c, k1, p1, "sha256:leaf", parent="sha256:mid")

    _resolve(c, "sha256:mid", m1.json()["proof_id"])
    body = c.get("/verify/sha256:leaf").json()
    assert body["status"] == "OK"
    assert [e["artifact_digest"] for e in body["chain"]] == [
        "sha256:leaf",
        "sha256:mid",
        "sha256:root",
    ]
    fork_entry = body["chain"][1]
    assert fork_entry["relation"] == "fork_point"
    assert fork_entry["resolution"]["selected_proof_id"] == m1.json()["proof_id"]
    # 顶层 applied_resolution 为路径上 (离目标最近的) 已应用裁决
    assert body["applied_resolution"]["id"] == fork_entry["resolution"]["id"]


def test_late_branch_invalidates_resolution(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    k3, p3 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    r1 = _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")

    _resolve(c, "sha256:child", r1.json()["proof_id"])
    assert c.get("/verify/sha256:child").json()["status"] == "OK"

    # 晚到的第三条分支 -> 裁决固化的集合 {r1, r2} 不再等于可见集合
    _post_proof(c, k3, p3, "sha256:child", parent="sha256:root")
    body = c.get("/verify/sha256:child").json()
    assert body["status"] == "FORK"
    assert len(body["failure"]["branches"]) == 3
    assert "applied_resolution" not in body

    # 针对新集合再次裁决 -> 恢复可验
    r1_again = c.get("/proofs/artifact/sha256:child").json()["proofs"]
    new_id = next(p["id"] for p in r1_again if p["issuer"] == p1)
    res2 = _resolve(c, "sha256:child", new_id, reason="三分支后重新裁决")
    body = c.get("/verify/sha256:child").json()
    assert body["status"] == "OK"
    assert body["applied_resolution"]["id"] == res2.json()["id"]
    assert len(body["applied_resolution"]["branch_proof_ids"]) == 3


def test_latest_matching_resolution_wins(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    r1 = _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    r2 = _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")

    # 先选 r1, 再追加一条选 r2 的裁决 (同一分支集合)
    _resolve(c, "sha256:child", r1.json()["proof_id"], reason="选 r1")
    _resolve(c, "sha256:child", r2.json()["proof_id"], reason="选 r2")
    body = c.get("/verify/sha256:child").json()
    assert body["status"] == "OK"
    assert body["applied_resolution"]["selected_proof_id"] == r2.json()["proof_id"]
    assert body["chain"][0]["issuer"] == p2


def test_resolved_branch_signature_still_checked(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    other, _ = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    good = _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    # 恶意分叉: issuer 是 p2 但用别的私钥签 -> 签名非法
    bad_sig = crypto.sign(other, "sha256:child", "sha256:root")
    bad = _post_proof(
        c, k2, p2, "sha256:child", parent="sha256:root", signature=bad_sig
    )

    _resolve(c, "sha256:child", bad.json()["proof_id"])
    body = c.get("/verify/sha256:child").json()
    assert body["status"] == "INVALID_SIGNATURE"
    # 裁决确实被应用 (选定非法分支), 只是后续验签失败
    assert body["applied_resolution"]["selected_proof_id"] == bad.json()["proof_id"]

    # 改选合法分支则验链通过
    _resolve(c, "sha256:child", good.json()["proof_id"], reason="改选合法分支")
    assert c.get("/verify/sha256:child").json()["status"] == "OK"


def test_resolved_fork_then_ancestor_revoked_failure_path(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    m1 = _post_proof(c, k1, p1, "sha256:mid", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:mid", parent="sha256:root")
    _post_proof(c, k1, p1, "sha256:leaf", parent="sha256:mid")
    _resolve(c, "sha256:mid", m1.json()["proof_id"])

    c.post(
        "/revocations",
        json={"artifact_digest": "sha256:root", "reason": "ROOT-ROTATED"},
    )
    body = c.get("/verify/sha256:leaf").json()
    assert body["status"] == "REVOKED"
    path = body["failure_path"]
    assert [e["artifact_digest"] for e in path] == [
        "sha256:leaf",
        "sha256:mid",
        "sha256:root",
    ]
    # 裁决先被应用, 之后沿选定分支才走到撤销的根
    assert path[1]["resolution"]["selected_proof_id"] == m1.json()["proof_id"]
    assert body["applied_resolution"]["id"] == path[1]["resolution"]["id"]


# ---------- GET /fork-resolutions/{artifact_digest} ----------


def test_list_resolutions_ordered(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    r1 = _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    r2 = _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")
    a = _resolve(c, "sha256:child", r1.json()["proof_id"], reason="A")
    b = _resolve(c, "sha256:child", r2.json()["proof_id"], reason="B")

    body = c.get("/fork-resolutions/sha256:child").json()
    assert body["status"] == "OK"
    assert [r["id"] for r in body["resolutions"]] == [
        a.json()["id"],
        b.json()["id"],
    ]
    assert body["resolutions"][1]["reason"] == "B"
    assert body["resolutions"][0]["branch_proof_ids"] == a.json()["branch_proof_ids"]


def test_list_resolutions_404(client):
    c, _ = client
    assert c.get("/fork-resolutions/sha256:nope").status_code == 404


# ---------- ?at= 历史时点与裁决 ----------

T0 = "2020-01-01T00:00:00.000Z"
T1 = "2020-01-01T01:00:00.000Z"
T2 = "2020-01-01T02:00:00.000Z"
T3 = "2020-01-01T03:00:00.000Z"
T4 = "2020-01-01T04:00:00.000Z"
T5 = "2020-01-01T05:00:00.000Z"


def test_at_resolution_not_visible_before_resolved_at(client):
    c, conn = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    r1 = _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")
    _set_created_at(conn, "sha256:root", T0)
    _set_created_at(conn, "sha256:child", T1, issuer=p1)
    _set_created_at(conn, "sha256:child", T2, issuer=p2)

    res = _resolve(c, "sha256:child", r1.json()["proof_id"])
    _set_resolved_at(conn, "sha256:child", T4, res.json()["id"])

    # T2: 两条分支均可见但裁决尚未产生 -> FORK
    body = c.get(f"/verify/sha256:child?at={T2}").json()
    assert body["status"] == "FORK"
    assert "applied_resolution" not in body

    # T3: 仍早于裁决 -> FORK
    assert c.get(f"/verify/sha256:child?at={T3}").json()["status"] == "FORK"

    # T4: resolved_at 边界 (闭区间) -> 裁决生效, 可继续验链
    body = c.get(f"/verify/sha256:child?at={T4}").json()
    assert body["status"] == "OK"
    assert body["applied_resolution"]["id"] == res.json()["id"]
    assert body["evaluated_at"] == T4

    # 实时同样 OK
    assert c.get("/verify/sha256:child").json()["status"] == "OK"


def test_at_late_branch_invalidates_historical_resolution(client):
    c, conn = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    k3, p3 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    r1 = _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")
    _set_created_at(conn, "sha256:root", T0)
    _set_created_at(conn, "sha256:child", T1, issuer=p1)
    _set_created_at(conn, "sha256:child", T2, issuer=p2)

    # T3 对 {r1, r2} 集合做出裁决
    res = _resolve(c, "sha256:child", r1.json()["proof_id"])
    _set_resolved_at(conn, "sha256:child", T3, res.json()["id"])

    body = c.get(f"/verify/sha256:child?at={T3}").json()
    assert body["status"] == "OK"

    # T5 晚到第三条分支 (created_at=T5): 裁决固化的两分支集合不再覆盖可见集合
    _post_proof(c, k3, p3, "sha256:child", parent="sha256:root")
    _set_created_at(conn, "sha256:child", T5, issuer=p3)

    # T3/T4 的历史结论不变 (新分支尚不可见)
    assert c.get(f"/verify/sha256:child?at={T4}").json()["status"] == "OK"
    # T5 起旧裁决失效 -> 重新 FORK
    body = c.get(f"/verify/sha256:child?at={T5}").json()
    assert body["status"] == "FORK"
    assert len(body["failure"]["branches"]) == 3
    assert c.get("/verify/sha256:child").json()["status"] == "FORK"


def test_at_branch_set_must_match_exactly(client):
    """裁决只覆盖两条分支的集合; 若某时点只可见其中一条 (单证明),
    根本没有分叉, 不应应用该裁决。"""
    c, conn = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    r1 = _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")
    _set_created_at(conn, "sha256:root", T0)
    _set_created_at(conn, "sha256:child", T1, issuer=p1)
    _set_created_at(conn, "sha256:child", T2, issuer=p2)

    res = _resolve(c, "sha256:child", r1.json()["proof_id"])
    _set_resolved_at(conn, "sha256:child", T3, res.json()["id"])

    # T1: 只可见第一条证明, 无分叉; 裁决集合 != 可见集合, 正常按单链验证,
    # 不附带 applied_resolution。
    body = c.get(f"/verify/sha256:child?at={T1}").json()
    assert body["status"] == "OK"
    assert "applied_resolution" not in body
    assert body["chain"][0].get("resolution") is None
