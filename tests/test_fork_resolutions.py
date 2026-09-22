"""分叉裁决 (fork resolution) 接口与校验语义的端到端测试。

覆盖:
- POST /fork-resolutions: 无分叉 409 / 非法选择 400 / 成功 201 与原子分支快照;
- 实时校验: 裁决前 FORK, 裁决后沿所选分支继续验链, 响应附带 applied_resolution;
- 祖先分叉裁决: chain 节点附带 resolution;
- 晚到分支使旧裁决失效 -> 重新 FORK; 重新裁决后恢复;
- 历史 ?at= 校验: 只采用该时点之前最新且分支集合完全一致的裁决,
  裁决前 FORK、裁决后可验链, 晚到分支不影响更早时点;
- GET /fork-resolutions/{digest} 按时间列出 (含已失效裁决)。
"""
from __future__ import annotations

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

# 固定历史时点 (均早于当前时间)。
T0 = "2020-01-01T00:00:00.000Z"
T1 = "2020-01-01T01:00:00.000Z"
T2 = "2020-01-01T02:00:00.000Z"
T3 = "2020-01-01T03:00:00.000Z"
T4 = "2020-01-01T04:00:00.000Z"
T5 = "2020-01-01T05:00:00.000Z"


@pytest.fixture()
def client():
    import sqlite3

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


def _proof_ids(client, artifact):
    rows = client.get(f"/proofs/artifact/{artifact}").json()["proofs"]
    return {r["id"]: r for r in rows}


def _resolve(client, artifact, selected_id, reason="investigated"):
    return client.post(
        "/fork-resolutions",
        json={
            "artifact_digest": artifact,
            "selected_proof_id": selected_id,
            "reason": reason,
        },
    )


def _set_proof_time(conn, artifact, ts, issuer=None):
    sql = "UPDATE proofs SET created_at = ? WHERE artifact_digest = ?"
    params: list = [ts, artifact]
    if issuer is not None:
        sql += " AND issuer = ?"
        params.append(issuer)
    conn.execute(sql, params)
    conn.commit()


def _set_resolution_time(conn, resolution_id, ts):
    conn.execute(
        "UPDATE fork_resolutions SET created_at = ? WHERE id = ?",
        (ts, resolution_id),
    )
    conn.commit()


def _make_target_fork(c):
    """root + child 的两条分叉证明 (两个签发者, 同一父节点)。

    返回 (k1, p1, k2, p2, ids)。
    """
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    assert _post_proof(c, k1, p1, "sha256:root").status_code == 201
    assert _post_proof(c, k1, p1, "sha256:child", parent="sha256:root").status_code == 201
    assert _post_proof(c, k2, p2, "sha256:child", parent="sha256:root").status_code == 201
    ids = _proof_ids(c, "sha256:child")
    return k1, p1, k2, p2, ids


# ---------- POST /fork-resolutions 校验语义 ----------


def test_resolution_no_fork_returns_409(client):
    c, _ = client
    k1, p1 = _keypair()
    _post_proof(c, k1, p1, "sha256:only")
    pid = _proof_ids(c, "sha256:only")
    r = _resolve(c, "sha256:only", next(iter(pid)))
    assert r.status_code == 409, r.text


def test_resolution_unknown_artifact_returns_409(client):
    c, _ = client
    r = _resolve(c, "sha256:nope", 1)
    assert r.status_code == 409


def test_resolution_invalid_proof_id_returns_400(client):
    c, _ = client
    _make_target_fork(c)
    root_ids = _proof_ids(c, "sha256:root")
    other_pid = next(iter(root_ids))  # 属于别的制品

    for bad in (999999, -1, other_pid):
        r = _resolve(c, "sha256:child", bad)
        assert r.status_code == 400, (bad, r.text)


def test_resolution_zero_proof_id_returns_400(client):
    c, _ = client
    _make_target_fork(c)
    r = _resolve(c, "sha256:child", 0)
    assert r.status_code == 400


def test_resolution_created_with_atomic_branch_snapshot(client):
    c, _ = client
    _, p1, _, p2, ids = _make_target_fork(c)
    # 选 p1 对应的分支
    selected = next(i for i, r in ids.items() if r["issuer"] == p1)
    r = _resolve(c, "sha256:child", selected, reason="use-canonical-branch")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["artifact_digest"] == "sha256:child"
    assert body["selected_proof_id"] == selected
    assert body["reason"] == "use-canonical-branch"
    assert sorted(body["branch_proof_ids"]) == sorted(ids)
    assert "created_at" in body
    # 追加记录: 可以再次裁决另一分支 (分叉仍存在)
    other = next(i for i, r in ids.items() if r["issuer"] == p2)
    r2 = _resolve(c, "sha256:child", other, reason="reconsider")
    assert r2.status_code == 201
    assert r2.json()["id"] > body["id"]


def test_resolution_append_only_keeps_history(client):
    c, _ = client
    _, p1, _, p2, ids = _make_target_fork(c)
    i1 = next(i for i, r in ids.items() if r["issuer"] == p1)
    i2 = next(i for i, r in ids.items() if r["issuer"] == p2)
    _resolve(c, "sha256:child", i1)
    _resolve(c, "sha256:child", i2)
    listing = c.get("/fork-resolutions/sha256:child").json()
    assert [x["selected_proof_id"] for x in listing["resolutions"]] == [i1, i2]


# ---------- 实时校验: 裁决后可继续验链 ----------


def test_fork_before_resolution_returns_fork(client):
    c, _ = client
    _make_target_fork(c)
    body = c.get("/verify/sha256:child").json()
    assert body["status"] == "FORK"
    assert body["applied_resolution"] is None
    assert len(body["failure"]["branches"]) == 2
    # 分支摘要带 proof_id
    assert {"proof_id", "signature_valid", "revoked"} <= set(
        body["failure"]["branches"][0]
    )


def test_fork_after_resolution_verifies_chain(client):
    c, _ = client
    _, p1, _, p2, ids = _make_target_fork(c)
    selected = next(i for i, r in ids.items() if r["issuer"] == p1)
    _resolve(c, "sha256:child", selected, reason="ok")

    body = c.get("/verify/sha256:child").json()
    assert body["status"] == "OK", body
    assert body["length"] == 2
    assert [e["artifact_digest"] for e in body["chain"]] == [
        "sha256:child",
        "sha256:root",
    ]
    target = body["chain"][0]
    assert target["relation"] == "target"
    assert target["issuer"] == p1  # 走所选分支
    res = body["applied_resolution"]
    assert res is not None
    assert res["selected_proof_id"] == selected
    assert sorted(res["branch_proof_ids"]) == sorted(ids)
    assert target["resolution"]["id"] == res["id"]


def test_resolution_can_select_either_branch(client):
    c, _ = client
    _, p1, _, p2, ids = _make_target_fork(c)
    selected = next(i for i, r in ids.items() if r["issuer"] == p2)
    _resolve(c, "sha256:child", selected)
    body = c.get("/verify/sha256:child").json()
    assert body["status"] == "OK"
    assert body["chain"][0]["issuer"] == p2


def test_late_branch_invalidates_resolution(client):
    c, _ = client
    _, p1, _, p2, ids = _make_target_fork(c)
    selected = next(i for i, r in ids.items() if r["issuer"] == p1)
    _resolve(c, "sha256:child", selected)
    assert c.get("/verify/sha256:child").json()["status"] == "OK"

    # 第三条不同证明晚到 (又一分支) -> 旧裁决分支集合不再完全一致 -> 失效
    k3, p3 = _keypair()
    _post_proof(c, k3, p3, "sha256:child", parent="sha256:root")
    body = c.get("/verify/sha256:child").json()
    assert body["status"] == "FORK"
    assert body["applied_resolution"] is None
    assert len(body["failure"]["branches"]) == 3

    # 对新三分支集合重新裁决后恢复
    new_ids = _proof_ids(c, "sha256:child")
    sel3 = next(i for i, r in new_ids.items() if r["issuer"] == p3)
    _resolve(c, "sha256:child", sel3, reason="new-set")
    body = c.get("/verify/sha256:child").json()
    assert body["status"] == "OK"
    assert body["chain"][0]["issuer"] == p3
    assert body["applied_resolution"]["reason"] == "new-set"


def test_resolution_at_ancestor_continues_chain(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    _post_proof(c, k1, p1, "sha256:mid", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:mid", parent="sha256:root")
    _post_proof(c, k1, p1, "sha256:leaf", parent="sha256:mid")

    # leaf 校验在祖先 mid 处 FORK
    body = c.get("/verify/sha256:leaf").json()
    assert body["status"] == "FORK"
    assert body["applied_resolution"] is None

    # 裁决 mid 的分叉
    mid_ids = _proof_ids(c, "sha256:mid")
    sel = next(i for i, r in mid_ids.items() if r["issuer"] == p1)
    _resolve(c, "sha256:mid", sel)

    body = c.get("/verify/sha256:leaf").json()
    assert body["status"] == "OK", body
    assert [e["artifact_digest"] for e in body["chain"]] == [
        "sha256:leaf",
        "sha256:mid",
        "sha256:root",
    ]
    # 顶层 applied_resolution 仅反映目标处 (leaf 未分叉) -> null
    assert body["applied_resolution"] is None
    # 祖先分叉点节点附带裁决
    mid_entry = body["chain"][1]
    assert mid_entry["relation"] == "ancestor"
    assert mid_entry["resolution"]["selected_proof_id"] == sel


def test_resolved_branch_with_bad_signature_still_fails(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    other, _ = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    # 第二条分支签名非法 (用别的私钥签)
    _post_proof(
        c, k2, p2, "sha256:child", parent="sha256:root",
        signature=crypto.sign(other, "sha256:child", "sha256:root"),
    )
    ids = _proof_ids(c, "sha256:child")
    bad = next(i for i, r in ids.items() if r["issuer"] == p2)
    _resolve(c, "sha256:child", bad)
    body = c.get("/verify/sha256:child").json()
    assert body["status"] == "INVALID_SIGNATURE"
    # 裁决被采用 (走到了签名校验), 顶层仍带 applied_resolution
    assert body["applied_resolution"]["selected_proof_id"] == bad


def test_resolution_on_forked_root(client):
    c, _ = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:r")
    _post_proof(c, k2, p2, "sha256:r")
    ids = _proof_ids(c, "sha256:r")
    sel = next(iter(ids))
    _resolve(c, "sha256:r", sel)
    body = c.get("/verify/sha256:r").json()
    assert body["status"] == "OK"
    assert body["length"] == 1
    assert body["chain"][0]["relation"] == "root"
    assert body["applied_resolution"]["selected_proof_id"] == sel


# ---------- GET /fork-resolutions/{digest} ----------


def test_list_resolutions_empty_404(client):
    c, _ = client
    assert c.get("/fork-resolutions/sha256:none").status_code == 404


def test_list_resolutions_ordered_by_time(client):
    c, _ = client
    _, p1, _, p2, ids = _make_target_fork(c)
    i1 = next(i for i, r in ids.items() if r["issuer"] == p1)
    i2 = next(i for i, r in ids.items() if r["issuer"] == p2)
    _resolve(c, "sha256:child", i1, reason="first")
    _resolve(c, "sha256:child", i2, reason="second")
    body = c.get("/fork-resolutions/sha256:child").json()
    assert body["status"] == "OK"
    assert body["artifact_digest"] == "sha256:child"
    reasons = [x["reason"] for x in body["resolutions"]]
    assert reasons == ["first", "second"]
    # 旧 (已可能失效) 裁决也仍然列出: append-only
    for x in body["resolutions"]:
        assert sorted(x["branch_proof_ids"]) == sorted(ids)


# ---------- 历史时点校验 (?at=) 与裁决 ----------


def test_resolution_history_before_and_after(client):
    c, conn = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")
    _set_proof_time(conn, "sha256:root", T0)
    _set_proof_time(conn, "sha256:child", T1, issuer=p1)
    _set_proof_time(conn, "sha256:child", T2, issuer=p2)

    ids = _proof_ids(c, "sha256:child")
    sel = next(i for i, r in ids.items() if r["issuer"] == p1)
    r = _resolve(c, "sha256:child", sel)
    _set_resolution_time(conn, r.json()["id"], T4)

    # T1: 只有单条证明 -> OK (无分叉)
    body = c.get(f"/verify/sha256:child?at={T1}").json()
    assert body["status"] == "OK"
    assert body["applied_resolution"] is None

    # T2: 两条分支均可见但尚未裁决 -> FORK
    body = c.get(f"/verify/sha256:child?at={T3}").json()
    assert body["status"] == "FORK"
    assert body["applied_resolution"] is None

    # T4: 裁决已作出且分支集合一致 -> 沿所选分支验链
    body = c.get(f"/verify/sha256:child?at={T4}").json()
    assert body["status"] == "OK"
    assert body["chain"][0]["issuer"] == p1
    res = body["applied_resolution"]
    assert res["selected_proof_id"] == sel
    assert body["evaluated_at"] == T4


def test_resolution_history_late_branch_not_retroactive(client):
    c, conn = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    k3, p3 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")
    _set_proof_time(conn, "sha256:root", T0)
    _set_proof_time(conn, "sha256:child", T1, issuer=p1)
    _set_proof_time(conn, "sha256:child", T2, issuer=p2)

    ids = _proof_ids(c, "sha256:child")
    sel = next(i for i, r in ids.items() if r["issuer"] == p1)
    r = _resolve(c, "sha256:child", sel)
    _set_resolution_time(conn, r.json()["id"], T3)

    # T3: 裁决生效
    assert c.get(f"/verify/sha256:child?at={T3}").json()["status"] == "OK"

    # 晚到的第三分支 (T5 才可见)
    _post_proof(c, k3, p3, "sha256:child", parent="sha256:root")
    _set_proof_time(conn, "sha256:child", T5, issuer=p3)

    # 实时校验: 旧裁决失效 -> FORK
    assert c.get("/verify/sha256:child").json()["status"] == "FORK"

    # T3/T4 历史时点: 第三分支尚不可见, 分支集合仍与裁决一致 -> 结论不变 (OK)
    body = c.get(f"/verify/sha256:child?at={T4}").json()
    assert body["status"] == "OK"
    assert body["applied_resolution"]["selected_proof_id"] == sel

    # T5: 三分支可见, 旧裁决集合不一致 -> 重新 FORK
    body = c.get(f"/verify/sha256:child?at={T5}").json()
    assert body["status"] == "FORK"
    assert body["applied_resolution"] is None


def test_resolution_history_only_latest_matching_used(client):
    c, conn = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    k3, p3 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    _post_proof(c, k1, p1, "sha256:child", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:child", parent="sha256:root")
    _set_proof_time(conn, "sha256:root", T0)
    _set_proof_time(conn, "sha256:child", T1, issuer=p1)
    _set_proof_time(conn, "sha256:child", T2, issuer=p2)

    ids = _proof_ids(c, "sha256:child")
    i1 = next(i for i, r in ids.items() if r["issuer"] == p1)
    i2 = next(i for i, r in ids.items() if r["issuer"] == p2)
    r1 = _resolve(c, "sha256:child", i1, reason="first")
    _set_resolution_time(conn, r1.json()["id"], T3)
    # 同一分支集合的第二次裁决: 选另一分支
    r2 = _resolve(c, "sha256:child", i2, reason="second")
    _set_resolution_time(conn, r2.json()["id"], T4)

    # T3: 只有第一条裁决 -> 选 p1
    body = c.get(f"/verify/sha256:child?at={T3}").json()
    assert body["status"] == "OK"
    assert body["chain"][0]["issuer"] == p1

    # T4: 采用该时点之前最新裁决 -> 选 p2
    body = c.get(f"/verify/sha256:child?at={T4}").json()
    assert body["status"] == "OK"
    assert body["chain"][0]["issuer"] == p2
    assert body["applied_resolution"]["reason"] == "second"

    # 晚到第三分支: 两条旧裁决的分支集合都不再一致 -> 全部失效
    _post_proof(c, k3, p3, "sha256:child", parent="sha256:root")
    _set_proof_time(conn, "sha256:child", T5, issuer=p3)
    body = c.get(f"/verify/sha256:child?at={T5}").json()
    assert body["status"] == "FORK"


def test_resolution_history_at_ancestor(client):
    c, conn = client
    k1, p1 = _keypair()
    k2, p2 = _keypair()
    _post_proof(c, k1, p1, "sha256:root")
    _post_proof(c, k1, p1, "sha256:mid", parent="sha256:root")
    _post_proof(c, k2, p2, "sha256:mid", parent="sha256:root")
    _post_proof(c, k1, p1, "sha256:leaf", parent="sha256:mid")
    _set_proof_time(conn, "sha256:root", T0)
    _set_proof_time(conn, "sha256:mid", T1, issuer=p1)
    _set_proof_time(conn, "sha256:mid", T2, issuer=p2)
    _set_proof_time(conn, "sha256:leaf", T2)

    mid_ids = _proof_ids(c, "sha256:mid")
    sel = next(i for i, r in mid_ids.items() if r["issuer"] == p1)
    r = _resolve(c, "sha256:mid", sel)
    _set_resolution_time(conn, r.json()["id"], T4)

    # T2: 祖先 mid 已分叉但裁决尚未作出 -> FORK
    body = c.get(f"/verify/sha256:leaf?at={T3}").json()
    assert body["status"] == "FORK"
    assert body["failure_path"][-1]["artifact_digest"] == "sha256:mid"

    # T4: 祖先分叉已被裁决 -> 继续向上验链
    body = c.get(f"/verify/sha256:leaf?at={T4}").json()
    assert body["status"] == "OK"
    mid_entry = next(e for e in body["chain"] if e["artifact_digest"] == "sha256:mid")
    assert mid_entry["resolution"]["selected_proof_id"] == sel
