"""证明链递归校验核心逻辑。

校验一个制品 A:
1. 必须存在至少一条证明记录, 否则 NOT_FOUND。
2. A 自身被撤销 -> REVOKED。
3. A 存在多条互不相同的证明 -> FORK (有向图在此处分叉)。
4. 证明的 Ed25519 签名必须通过, 否则 INVALID_SIGNATURE。
5. 沿 parent_digest 向上:
   - 父节点缺失 / 分叉 / 被撤销 / 签名非法 / 成环 / 非信任根,
     全部带上可定位的有序失败路径返回。
6. 根记录 (parent_digest 为空) 的 issuer 必须属于信任根集合
   (cfg.trusted_root_issuers); 该集合由入口解析: 可来自指定/激活的
   信任根版本 (见 /trust-roots) 或 TRUSTED_ROOT_ISSUERS,
   集合为空时退化为“任意自签名根均可接受”(仅建议开发环境使用)。

分叉裁决 (fork resolution):
- 分叉本身不自动选择分支; 可通过 POST /fork-resolutions 追加裁决,
  固化裁决时该制品全部分支的 proof_id 集合 (只追加, 不修改不删除)。
- 实时校验与 ?at= 历史校验遇到分叉时, 只采用“评估时点之前最新、且其
  分支 proof_id 集合与当时可见证明集合完全一致”的裁决:
    * 裁决前 (无任何适用裁决) -> 仍返回 FORK;
    * 裁决后 -> 沿裁决选定的证明继续验链, 响应附带 applied_resolution;
    * 任何晚到分支都会扩大可见集合, 旧裁决集合不再相等而失效,
      重新返回 FORK (直到有人针对新分支集合追加新裁决)。
- 历史校验中裁决与证明一样受 resolved_at <= at / created_at <= at 约束,
  晚到的裁决不改变更早时点的结论。

历史时点校验 (at 参数):
- 只读取 created_at <= at 的证明记录, 仅 revoked_at <= at 的撤销视为生效;
  因此晚到的分叉/父证明与后续撤销都不会改变更早时点的结论。
- 响应中附带 evaluated_at (归一化后的 UTC 毫秒串), 不传 at 时不附带。
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from . import crypto
from .config import Settings, settings as default_settings
from .database import fetch_fork_resolutions, fetch_proofs, fetch_revocation
from .timeutil import format_utc_ms

# verdict 状态码
OK = "OK"
NOT_FOUND = "NOT_FOUND"
REVOKED = "REVOKED"
FORK = "FORK"
INVALID_SIGNATURE = "INVALID_SIGNATURE"
MISSING_PARENT = "MISSING_PARENT"
UNTRUSTED_ROOT = "UNTRUSTED_ROOT"
CYCLE = "CYCLE"
MAX_DEPTH_EXCEEDED = "MAX_DEPTH_EXCEEDED"


@dataclass
class _TraceResult:
    """单条分支向上追溯到终止点的结果。"""

    verdict: str
    failure: dict[str, Any]
    ancestors: list[dict[str, Any]] = field(default_factory=list)


def _entry(
    record: dict[str, Any],
    relation: str,
    revocation: dict[str, Any] | None = None,
    resolution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "artifact_digest": record["artifact_digest"],
        "issuer": record["issuer"],
        "parent_digest": record["parent_digest"],
        "relation": relation,
        "revocation": revocation,
    }
    # 仅被裁决消解的分叉点条目才附带裁决, 其余条目形状保持不变。
    if resolution is not None:
        out["resolution"] = resolution
    return out


def _terminal_failure(
    verdict: str,
    detail: str,
    record: dict[str, Any] | None,
    relation: str = "failure_point",
    revocation: dict[str, Any] | None = None,
    resolution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "code": verdict,
        "detail": detail,
    }
    if record is not None:
        out["at"] = _entry(record, relation, revocation, resolution)
    return out


def _same_record(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return (
        a["issuer"] == b["issuer"]
        and (a["parent_digest"] or None) == (b["parent_digest"] or None)
        and a["signature"] == b["signature"]
    )


def _dedupe(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """唯一索引已保证内容不重复, 这里仅做防御性去重。"""
    unique: list[dict[str, Any]] = []
    for rec in records:
        if not any(_same_record(rec, u) for u in unique):
            unique.append(rec)
    return unique


def _applicable_resolution(
    conn: sqlite3.Connection,
    artifact_digest: str,
    visible_records: list[dict[str, Any]],
    at: str | None,
) -> dict[str, Any] | None:
    """返回适用于当前可见分支集合的最新裁决; 不存在适用裁决时返回 None。

    适用条件 (实时校验与 ?at= 历史校验一致):
    - 裁决在评估时点之前已可见 (resolved_at <= at);
    - 裁决原子固化的分支 proof_id 集合与当时可见的证明集合 *完全一致*。

    任何晚到分支都会扩大可见集合, 使旧裁决固化的集合不再相等而失效;
    更早的裁决即使集合碰巧再次相等也只在没有更新的匹配裁决时才被采用。
    """
    visible_ids = {r["id"] for r in visible_records}
    resolutions = fetch_fork_resolutions(conn, artifact_digest, at=at)
    for resolution in reversed(resolutions):  # fetch 返回旧 -> 新, 反向取最新
        if set(resolution["branch_proof_ids"]) == visible_ids:
            return resolution
    return None


def _applied_resolution(
    path: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """沿 target -> root 的有序路径, 取首个 (离目标最近的) 已应用裁决。"""
    for entry in path:
        resolution = entry.get("resolution")
        if resolution is not None:
            return resolution
    return None


def _with_applied_resolution(
    result: dict[str, Any],
    path: list[dict[str, Any]],
) -> dict[str, Any]:
    """若路径上存在被应用的裁决, 在顶层附带 applied_resolution。"""
    applied = _applied_resolution(path)
    if applied is not None:
        result["applied_resolution"] = applied
    return result


def _branch_summary(
    conn: sqlite3.Connection,
    record: dict[str, Any],
    at: str | None = None,
) -> dict[str, Any]:
    """分叉点处单条分支的即时摘要 (签名/撤销状态)。"""
    sig_ok = crypto.verify(
        record["issuer"],
        record["artifact_digest"],
        record["parent_digest"],
        record["signature"],
    )
    rev = fetch_revocation(conn, record["artifact_digest"], at=at)
    return {
        "artifact_digest": record["artifact_digest"],
        "issuer": record["issuer"],
        "parent_digest": record["parent_digest"],
        "signature_valid": sig_ok,
        "revoked": rev is not None,
    }


def _trace_terminus(
    conn: sqlite3.Connection,
    start: dict[str, Any],
    cfg: Settings,
    at: str | None = None,
) -> _TraceResult:
    """从某条证明的父节点开始向上追溯, 直到根或发现故障点。

    返回故障 verdict/failure 以及经过的祖先节点 (不含起点, 含终止点)。
    """
    ancestors: list[dict[str, Any]] = []
    current_parent = start["parent_digest"]
    visited: set[str] = set()  # 用于成环检测
    depth = 0

    while True:
        depth += 1
        if depth > cfg.max_chain_depth:
            return _TraceResult(
                MAX_DEPTH_EXCEEDED,
                _terminal_failure(
                    MAX_DEPTH_EXCEEDED,
                    f"链长度超过上限 {cfg.max_chain_depth}",
                    None,
                ),
                ancestors,
            )

        records = _dedupe(fetch_proofs(conn, current_parent, at=at))
        if not records:
            failure = _terminal_failure(
                MISSING_PARENT,
                f"制品 {current_parent} 没有任何证明记录",
                None,
            )
            failure["missing_artifact"] = current_parent
            return _TraceResult(MISSING_PARENT, failure, ancestors)

        # 祖先节点出现分叉。仅当存在与当时可见分支集合完全一致的最新裁决时
        # 才沿选定分支继续; 否则在此处返回 FORK。
        resolution: dict[str, Any] | None = None
        if len(records) > 1:
            resolution = _applicable_resolution(
                conn, current_parent, records, at
            )
            if resolution is None:
                rec = records[0]
                ancestors.append(_entry(rec, "fork_point"))
                return _TraceResult(
                    FORK,
                    {
                        "code": FORK,
                        "detail": f"祖先制品 {current_parent} 存在 {len(records)} 条分叉证明",
                        "at": ancestors[-1],
                        "branches": [
                            _branch_summary(conn, r, at=at) for r in records
                        ],
                    },
                    ancestors,
                )
            record = next(
                r
                for r in records
                if r["id"] == resolution["selected_proof_id"]
            )
            # 分叉点条目只追加一次; 后续撤销/签名/根检查复用同一条目,
            # 不再按普通祖先重复追加。
            ancestors.append(_entry(record, "fork_point", resolution=resolution))
        else:
            record = records[0]

        digest = record["artifact_digest"]

        # 成环优先判定, 避免在环内重复做签名/撤销检查。
        if digest in visited:
            if resolution is None:
                ancestors.append(_entry(record, "cycle_point"))
            return _TraceResult(
                CYCLE,
                {
                    "code": CYCLE,
                    "detail": f"父链在制品 {digest} 处形成环",
                    "at": ancestors[-1],
                },
                ancestors,
            )
        visited.add(digest)

        # 已裁决分叉点的条目已以 fork_point 关系追加, 故障终止时复用该
        # 唯一条目 (不重复追加); failure.at 仍标记 fork_point 以保留分叉
        # 定位语义, 并携带 resolution / revocation 详情。
        def _terminate(
            verdict: str,
            detail: str,
            relation: str,
            revocation: dict[str, Any] | None = None,
        ) -> _TraceResult:
            if resolution is None:
                ancestors.append(
                    _entry(record, relation, revocation, resolution)
                )
            return _TraceResult(
                verdict,
                _terminal_failure(
                    verdict,
                    detail,
                    record,
                    "fork_point" if resolution is not None else relation,
                    revocation,
                    resolution,
                ),
                ancestors,
            )

        rev = fetch_revocation(conn, digest, at=at)
        if rev:
            relation = (
                "revoked"
                if digest == start["artifact_digest"]
                else "revoked_ancestor"
            )
            if resolution is not None:
                # 在已追加的 fork_point 条目上补充撤销信息。
                ancestors[-1]["revocation"] = rev
            return _terminate(
                REVOKED, f"制品 {digest} 已被撤销: {rev['reason']}", relation, rev
            )

        sig_ok = crypto.verify(
            record["issuer"],
            record["artifact_digest"],
            record["parent_digest"],
            record["signature"],
        )
        if not sig_ok:
            return _terminate(
                INVALID_SIGNATURE,
                f"制品 {digest} 的 Ed25519 签名验证失败",
                "failure_point",
            )

        # 到达根。
        if not record["parent_digest"]:
            if cfg.trusted_root_issuers and (
                record["issuer"] not in cfg.trusted_root_issuers
            ):
                return _terminate(
                    UNTRUSTED_ROOT,
                    f"根制品 {digest} 的签发者不在信任根集合中",
                    "untrusted_root",
                )
            if resolution is None:
                ancestors.append(_entry(record, "root"))
            return _TraceResult(OK, {}, ancestors)

        if resolution is None:
            ancestors.append(_entry(record, "ancestor"))
        current_parent = record["parent_digest"]


def verify_artifact(
    conn: sqlite3.Connection,
    artifact_digest: str,
    cfg: Settings | None = None,
    at: datetime | None = None,
) -> dict[str, Any]:
    """校验入口, 返回可直接序列化为 JSON 的结果字典。

    at 为历史时点 (UTC datetime); 传入时只基于该时点已可见的数据求值,
    并在结果中附带 evaluated_at。
    """
    cfg = cfg or default_settings
    at_ts = format_utc_ms(at) if at is not None else None
    result = _evaluate(conn, artifact_digest.strip(), cfg, at_ts)
    if at_ts is not None:
        result["evaluated_at"] = at_ts
    return result


def _evaluate(
    conn: sqlite3.Connection,
    digest: str,
    cfg: Settings,
    at: str | None,
) -> dict[str, Any]:
    """在 (可选的) 历史时点 at 上执行完整校验。at 为已归一化的 UTC 毫秒串。"""
    records = _dedupe(fetch_proofs(conn, digest, at=at))
    if not records:
        return {
            "artifact_digest": digest,
            "status": NOT_FOUND,
            "failure": _terminal_failure(
                NOT_FOUND, f"制品 {digest} 不存在任何证明记录", None
            ),
            "chain": [],
        }

    # 目标制品自身被撤销 (无论有几条证明)。
    rev = fetch_revocation(conn, digest, at=at)
    if rev:
        record = records[0]
        return {
            "artifact_digest": digest,
            "status": REVOKED,
            "failure": _terminal_failure(
                REVOKED,
                f"制品 {digest} 已被撤销: {rev['reason']}",
                record,
                "revoked",
                rev,
            ),
            "chain": [],
        }

    # 目标制品处出现分叉: 存在适用裁决则沿选定分支继续验链, 否则返回 FORK。
    target_resolution: dict[str, Any] | None = None
    if len(records) > 1:
        target_resolution = _applicable_resolution(conn, digest, records, at)
        if target_resolution is None:
            return {
                "artifact_digest": digest,
                "status": FORK,
                "failure": {
                    "code": FORK,
                    "detail": f"制品 {digest} 存在 {len(records)} 条分叉证明, 信任链不唯一",
                    "at": _entry(records[0], "fork_point"),
                    "branches": [
                        _branch_summary(conn, r, at=at) for r in records
                    ],
                },
                "chain": [],
            }
        record = next(
            r
            for r in records
            if r["id"] == target_resolution["selected_proof_id"]
        )
    else:
        record = records[0]

    # 目标证明签名校验。
    sig_ok = crypto.verify(
        record["issuer"],
        record["artifact_digest"],
        record["parent_digest"],
        record["signature"],
    )
    if not sig_ok:
        result = {
            "artifact_digest": digest,
            "status": INVALID_SIGNATURE,
            "failure": _terminal_failure(
                INVALID_SIGNATURE,
                f"制品 {digest} 的 Ed25519 签名验证失败",
                record,
                "failure_point",
                None,
                target_resolution,
            ),
            "chain": [],
        }
        # 分叉裁决已应用但选定分支自身签名非法时, 仍说明采用了哪条裁决。
        return _with_applied_resolution(
            result, [_entry(record, "target", resolution=target_resolution)]
        )

    target_entry = _entry(record, "target", resolution=target_resolution)

    # 根证明。
    if not record["parent_digest"]:
        if cfg.trusted_root_issuers and (
            record["issuer"] not in cfg.trusted_root_issuers
        ):
            return {
                "artifact_digest": digest,
                "status": UNTRUSTED_ROOT,
                "failure": _terminal_failure(
                    UNTRUSTED_ROOT,
                    f"根制品 {digest} 的签发者不在信任根集合中",
                    record,
                    "untrusted_root",
                    None,
                    target_resolution,
                ),
                "chain": [],
            }
        root_entry = _entry(record, "root", resolution=target_resolution)
        return _with_applied_resolution(
            {
                "artifact_digest": digest,
                "status": OK,
                "chain": [root_entry],
                "root_issuer": record["issuer"],
                "length": 1,
            },
            [root_entry],
        )

    trace = _trace_terminus(conn, record, cfg, at=at)
    if trace.verdict != OK:
        result = {
            "artifact_digest": digest,
            "status": trace.verdict,
            "failure": trace.failure,
            # 失败路径: 目标 -> 已验证的祖先 (含被裁决消解的分叉点) -> 故障点
            "failure_path": [target_entry, *trace.ancestors],
            "chain": [],
        }
        return _with_applied_resolution(
            result, [target_entry, *trace.ancestors]
        )

    chain = [target_entry, *trace.ancestors]
    return _with_applied_resolution(
        {
            "artifact_digest": digest,
            "status": OK,
            "chain": chain,
            "root_issuer": trace.ancestors[-1]["issuer"],
            "length": len(chain),
        },
        chain,
    )
