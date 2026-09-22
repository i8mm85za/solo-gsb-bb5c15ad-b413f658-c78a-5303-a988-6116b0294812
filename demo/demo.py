#!/usr/bin/env python3
"""端到端演示: 生成密钥 -> 写入根/子证明 -> 校验 -> 制造分叉/撤销 -> 观察失败路径
-> 分叉裁决 -> 裁决后恢复验链。

仅依赖标准库 + cryptography (容器内已安装)。
用法:
    python demo/demo.py                 # 默认 http://127.0.0.1:8080
    BASE_URL=http://localhost:8080 python demo/demo.py
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import crypto  # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8080")


def _request(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def post_proof(priv, pub, artifact: str, parent: str | None = None) -> dict:
    sig = crypto.sign(priv, artifact, parent)
    status, body = _request(
        "POST",
        "/proofs",
        {
            "artifact_digest": artifact,
            "issuer": pub,
            "parent_digest": parent,
            "signature": sig,
        },
    )
    assert status in (200, 201), body
    return body


def show(title: str, status: int, body: dict) -> None:
    print(f"\n=== {title} (HTTP {status}) ===")
    print(json.dumps(body, indent=2, ensure_ascii=False))


def main() -> None:
    print(f"目标 API: {BASE_URL}")
    print("健康检查:", _request("GET", "/health"))

    # 一条链上的签名密钥 (实际场景中根密钥应独立保管)
    root_priv = Ed25519PrivateKey.generate()
    root_pub = crypto.encode_public_key(root_priv.public_key())
    other_priv = Ed25519PrivateKey.generate()
    other_pub = crypto.encode_public_key(other_priv.public_key())

    tag = format(id(object()) % 0xFFFFFF, "06x")
    root = f"sha256:baseos-{tag}"
    mid = f"sha256:app-{tag}"
    leaf = f"sha256:image-{tag}"

    # 1) 写入有序信任链 root -> mid -> leaf
    post_proof(root_priv, root_pub, root)
    post_proof(root_priv, root_pub, mid, parent=root)
    post_proof(root_priv, root_pub, leaf, parent=mid)

    status, body = _request("GET", f"/verify/{leaf}")
    show("成功: 完整有序信任链 (target -> root)", status, body)

    # 2) 祖先被撤销
    status, body = _request(
        "POST", "/revocations", {"artifact_digest": root, "reason": "密钥轮换演示"}
    )
    show("撤销根制品", status, body)

    status, body = _request("GET", f"/verify/{leaf}")
    show("失败: 撤销祖先, 带可定位 failure_path", status, body)

    # 3) 分叉: 新链, 同一制品出现两条不同证明
    r2 = f"sha256:baseos2-{tag}"
    m2 = f"sha256:app2-{tag}"
    l2 = f"sha256:image2-{tag}"
    post_proof(root_priv, root_pub, r2)
    post_proof(root_priv, root_pub, m2, parent=r2)
    post_proof(root_priv, root_pub, l2, parent=m2)
    # 另一签发者对 m2 给出指向同一父节点的不同证明
    post_proof(other_priv, other_pub, m2, parent=r2)

    status, body = _request("GET", f"/verify/{l2}")
    show("失败: 祖先分叉 FORK, branches 列出全部候选", status, body)

    # 4) 分叉裁决: 追加裁决选定 root_priv 对 m2 的证明, 验链恢复;
    #    随后一条晚到的第三分支使旧裁决失效, 重新返回 FORK。
    r3 = f"sha256:baseos3-{tag}"
    m3 = f"sha256:app3-{tag}"
    l3 = f"sha256:image3-{tag}"
    post_proof(root_priv, root_pub, r3)
    chosen = post_proof(root_priv, root_pub, m3, parent=r3)
    post_proof(other_priv, other_pub, m3, parent=r3)
    post_proof(root_priv, root_pub, l3, parent=m3)

    status, body = _request("GET", f"/verify/{l3}")
    show("裁决前: 祖先分叉 FORK", status, body)

    status, resolution = _request(
        "POST",
        "/fork-resolutions",
        {
            "artifact_digest": m3,
            "selected_proof_id": chosen["proof_id"],
            "reason": "演示: 采用官方签发者 root_priv 的构建证明",
        },
    )
    show("追加分叉裁决 (原子固化当时全部分支 proof_id)", status, resolution)

    status, body = _request("GET", f"/verify/{l3}")
    show("裁决后: 沿选定分支继续验链 OK, 附带 applied_resolution", status, body)

    status, body = _request("GET", f"/fork-resolutions/{m3}")
    show("按时间列出该制品的全部裁决", status, body)

    print("\n演示完成。")


if __name__ == "__main__":
    main()
