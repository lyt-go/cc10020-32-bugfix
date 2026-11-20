"""接入质量校验领域服务：字段级校验、完整性检查、阈值告警与阻断策略。

提供转换后数据的质量校验能力，包括必填字段检查、类型校验、
数值范围校验和完整性评分。
跨模块关联：data_transform（转换后校验）、batch_ingest（批量质量检查）。

质量检查凭证（voucher）持久化
-----------------------------
每次校验都会生成一份「质量检查凭证」并写入 json_store 的
``quality_check_voucher`` 分区，替代原先只存在进程内存里的
``_validation_history``，因此：

- 提前返回的阻断结论与正常通过的结论一样会被持久化；
- 服务重启、实例重建后历史凭证仍可查询；
- 同一次校验（相同校验目标指纹+周期）并发重试时只确认一份有效结论，
  运行中的检查不会被重试请求覆盖。

凭证结构同时兼容历史字段：读取时通过 ``_normalize_voucher`` 把早期
内存/磁盘里的旧形态（``passed`` 布尔、``outcome=blocked`` 等）归一化为
统一的 ``status/outcome`` 形态。
"""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from app.persistence import json_store
from app.services.base import BaseModuleService

# 质量检查凭证持久化分区
VOUCHER_KEY = "quality_check_voucher"

# 凭证生命周期状态
STATUS_RUNNING = "运行中"
STATUS_CONFIRMED = "已确认"

# 已确认结论
OUTCOME_PASSED = "passed"
OUTCOME_BLOCKED = "blocked"
OUTCOME_FAILED = "failed"

CONFIRMED_OUTCOMES = {OUTCOME_PASSED, OUTCOME_BLOCKED, OUTCOME_FAILED}


class DataQualityRuleService(BaseModuleService):
    MODULE = "data_quality_rule"
    ENTITY = "质量规则"
    OPERATION_TERM = "校验"
    LIST_FIELDS = ["规则编号", "数据来源", "校验字段", "校验表达式", "阈值下界", "阈值上界", "阻断策略", "规则版本"]
    REQUIRED_FIELDS = ["规则编号", "数据来源", "校验字段"]
    STATUS_ORDER = ["草稿", "待校验", "已生效", "已停用"]
    ACTION_RULES = {"提交校验": "待校验", "标记生效": "已生效", "停用规则": "已停用"}
    NEGATIVE_ACTIONS = ["停用规则"]

    # ─────────────────────────────────────────────
    # 凭证兼容与指纹
    # ─────────────────────────────────────────────
    @staticmethod
    def _normalize_voucher(voucher: dict[str, Any]) -> dict[str, Any]:
        """把历史凭证形态归一化为当前凭证结构（兼容旧数据）。"""
        normalized = dict(voucher)
        status = normalized.get("status")
        outcome = normalized.get("outcome")

        # 历史上阻断只记 outcome=blocked 而没有统一状态
        if not status:
            if outcome in CONFIRMED_OUTCOMES:
                status = STATUS_CONFIRMED
            elif normalized.get("confirmed_at"):
                status = STATUS_CONFIRMED
            elif "passed" in normalized and normalized.get("passed") is not None:
                # 历史凭证只保留 passed 布尔、没有状态字段，视为已确认结论
                status = STATUS_CONFIRMED
            else:
                status = STATUS_RUNNING
        normalized["status"] = status

        # 历史布尔结论 -> 统一 outcome 枚举
        if outcome not in CONFIRMED_OUTCOMES:
            if normalized.get("blocked") is True or outcome == "blocked":
                normalized["outcome"] = OUTCOME_BLOCKED
            elif normalized.get("passed") is False:
                normalized["outcome"] = OUTCOME_FAILED
            elif normalized.get("passed") is True:
                normalized["outcome"] = OUTCOME_PASSED
        if "outcome" not in normalized:
            normalized["outcome"] = None

        normalized.setdefault("check_fingerprint",
                              DataQualityRuleService._short_fingerprint(
                                  str(normalized.get("id", "")),
                                  str(normalized.get("source_module", "")),
                                  str(normalized.get("record_fingerprint", "")),
                                  str(normalized.get("cycle_id", "")),
                              ))
        normalized.setdefault("credential_fingerprint", "")
        normalized.setdefault("rule_digest", "")
        normalized.setdefault("cycle_id", "")
        normalized.setdefault("details", [])
        normalized.setdefault("checks", 0)
        normalized.setdefault("failed", 0)
        normalized.setdefault("passed_checks", 0)
        normalized.setdefault("score", 0)
        normalized.setdefault("blocked", normalized.get("outcome") == OUTCOME_BLOCKED)
        return normalized

    @staticmethod
    def _short_fingerprint(*parts: str) -> str:
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _rule_digest(rules: list[dict[str, Any]]) -> str:
        """对参与校验的规则集生成摘要，凭证可据此复现当时的规则口径。"""
        basis = [
            f"{r.get('规则编号')}:{r.get('校验字段')}:{r.get('校验表达式')}:"
            f"{r.get('阈值下界')}:{r.get('阈值上界')}:{r.get('阻断策略')}:{r.get('规则版本')}"
            for r in rules
        ]
        return hashlib.sha256("\n".join(basis).encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _credential_fingerprint(payload: dict[str, Any]) -> str:
        """对已确认结论生成凭证指纹，发布后可按指纹复核数据未被篡改。"""
        canonical = hashlib.sha256(
            str(sorted(payload.items(), key=lambda kv: str(kv[0]))).encode("utf-8")
        ).hexdigest()
        return canonical

    # ─────────────────────────────────────────────
    # 持久化的校验生命周期：启动 / 确认 / 重试
    # ─────────────────────────────────────────────
    def start_validation(
        self,
        record: dict[str, Any],
        source_module: str = "",
        cycle_id: str | None = None,
    ) -> dict[str, Any]:
        """启动一次质量校验并落库「运行中」凭证。

        并发重试同一次校验时：
        - 已存在已确认凭证：直接返回该有效结论，不产生新凭证；
        - 已存在运行中凭证：复用该凭证，仅刷新重试计数，不覆盖原检查。
        """
        cycle_id = cycle_id or f"cycle-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
        record_fp = self._short_fingerprint(str(sorted(record.items(), key=lambda kv: str(kv[0]))))
        check_fp = self._short_fingerprint(record_fp, source_module, cycle_id)

        rules = self._matching_rules(source_module)
        matching = rules
        now = datetime.now(timezone.utc).isoformat()
        serial = len(json_store.get_all(VOUCHER_KEY)) + 1
        voucher = {
            "检查编号": f"QC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{serial:05d}",
            "status": STATUS_RUNNING,
            "outcome": None,
            "passed": None,
            "blocked": False,
            "source_module": source_module,
            "cycle_id": cycle_id,
            "record_preview": str(record)[:200],
            "record_fingerprint": record_fp,
            "check_fingerprint": check_fp,
            "rule_digest": self._rule_digest(matching),
            "rules_applied": [r.get("规则编号") for r in matching],
            "checks": len(matching),
            "failed": 0,
            "passed_checks": 0,
            "score": None,
            "details": [],
            "retries": 0,
            "started_at": now,
            "confirmed_at": None,
            "credential_fingerprint": "",
        }
        # 原子检查-插入：并发重试同一次校验只会落一份凭证
        saved, inserted = json_store.insert_if_absent(
            VOUCHER_KEY,
            predicate=lambda r: r.get("check_fingerprint") == check_fp,
            record=voucher,
        )
        saved = self._normalize_voucher(saved)
        if inserted:
            return saved
        if saved["status"] == STATUS_CONFIRMED:
            saved["_reused"] = "confirmed"
            return saved
        # 运行中的同一检查被重试：复用凭证，仅累计重试次数
        json_store.update(VOUCHER_KEY, int(saved["id"]), {
            "retries": int(saved.get("retries", 0)) + 1,
            "last_retry_at": datetime.now(timezone.utc).isoformat(),
        })
        refreshed = self._normalize_voucher(json_store.get_by_id(VOUCHER_KEY, int(saved["id"])))
        refreshed["_reused"] = "running"
        return refreshed

    def confirm_validation(
        self,
        check_id: int,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """确认一次校验的最终结论（通过/失败/阻断），持久化凭证。

        采用存储锁内的 compare-and-set：只有「运行中」凭证可以被确认。
        并发重试下第二个确认请求不会覆盖第一个结论，而是返回已确认的
        有效凭证，保证同一次校验只有一份有效结论。
        """
        voucher = json_store.get_by_id(VOUCHER_KEY, check_id)
        if voucher is None:
            raise ValueError(f"质量检查凭证 {check_id} 不存在")
        voucher = self._normalize_voucher(voucher)

        if voucher["status"] == STATUS_CONFIRMED:
            voucher["_reused"] = "confirmed"
            return voucher

        blocked = bool(result.get("blocked"))
        if blocked:
            outcome = OUTCOME_BLOCKED
        elif result.get("passed", True):
            outcome = OUTCOME_PASSED
        else:
            outcome = OUTCOME_FAILED

        confirmed_at = datetime.now(timezone.utc).isoformat()
        fingerprint_payload = {
            "检查编号": voucher.get("检查编号"),
            "check_fingerprint": voucher.get("check_fingerprint"),
            "rule_digest": voucher.get("rule_digest"),
            "outcome": outcome,
            "checks": result.get("checks", voucher.get("checks", 0)),
            "failed": result.get("failed", 0),
            "passed_checks": result.get("passed_checks", 0),
            "score": result.get("score", 0),
            "blocked": blocked,
            "confirmed_at": confirmed_at,
        }
        updates = {
            "status": STATUS_CONFIRMED,
            "outcome": outcome,
            "passed": outcome == OUTCOME_PASSED,
            "blocked": blocked,
            "checks": result.get("checks", voucher.get("checks", 0)),
            "failed": result.get("failed", 0),
            "passed_checks": result.get("passed_checks", 0),
            "score": result.get("score", 0),
            "details": result.get("details", []),
            "confirmed_at": confirmed_at,
            "credential_fingerprint": self._credential_fingerprint(fingerprint_payload),
        }

        confirmed = json_store.update_if(
            VOUCHER_KEY,
            check_id,
            predicate=lambda r: self._normalize_voucher(r).get("status") == STATUS_RUNNING,
            updates=updates,
        )
        if confirmed is None:
            # 已被并发请求抢先确认：返回那份有效结论，不重复确认
            latest = self._normalize_voucher(json_store.get_by_id(VOUCHER_KEY, check_id))
            latest["_reused"] = "confirmed"
            return latest
        return self._normalize_voucher(confirmed)

    # ─────────────────────────────────────────────
    # 校验执行（保留原有同步接口，内部走凭证生命周期）
    # ─────────────────────────────────────────────
    def _matching_rules(self, source_module: str) -> list[dict[str, Any]]:
        rules = json_store.get_all(self.MODULE)
        return [
            r for r in rules
            if r.get("status") == "已生效"
            and (str(r.get("数据来源", "")) in (source_module, "", "ALL", "*")
                 or source_module == ""
                 or not source_module)
        ]

    def validate_record(self, record: dict[str, Any], source_module: str = "",
                        cycle_id: str | None = None) -> dict[str, Any]:
        """对单条记录执行质量校验，并持久化质量检查凭证。

        校验流程：
        1. 加载与该来源相关的已生效规则
        2. 逐条规则执行校验表达式
        3. 检查数值范围（阈值上下界）
        4. 根据阻断策略决定是否拒绝（阻断也会先落库凭证再提前返回）

        Returns:
            { passed, checks, failed, details, score, check_id, 凭证编号, ... }
        """
        matching = self._matching_rules(source_module)

        # 无生效规则：没有实际检查项，不生成检查凭证（分母为 0 的检查不应计入统计）
        if not matching:
            return {"passed": True, "checks": 0, "failed": 0, "details": [], "score": 100}

        voucher = self.start_validation(record, source_module=source_module, cycle_id=cycle_id)
        # 重试命中已确认凭证：直接复用既有有效结论
        if voucher.get("status") == STATUS_CONFIRMED:
            return self._voucher_to_result(voucher)
        check_id = int(voucher["id"])

        results: list[dict[str, Any]] = []
        total_passed = 0
        total_failed = 0

        for rule in matching:
            field = str(rule.get("校验字段", ""))
            expression = str(rule.get("校验表达式", ""))
            block_policy = str(rule.get("阻断策略", "警告"))
            try:
                lower = float(rule.get("阈值下界", "0") or "0")
                upper = float(rule.get("阈值上界", "0") or "0")
            except ValueError:
                lower = 0
                upper = 0

            check_result = self._execute_check(record, field, expression)
            range_check = self._check_range(record, field, lower, upper)

            passed = check_result.get("passed", True) and range_check.get("passed", True)
            detail = {
                "rule_no": rule.get("规则编号"),
                "field": field,
                "expression": expression,
                "passed": passed,
                "expr_result": check_result,
                "range_result": range_check,
                "block_policy": block_policy,
            }
            results.append(detail)

            if passed:
                total_passed += 1
                continue

            total_failed += 1
            partial = {
                "passed": False,
                "checks": len(matching),
                "failed": total_failed,
                "passed_checks": total_passed,
                "details": results,
                "score": max(0, 100 - total_failed * 10),
            }
            if block_policy == "阻断":
                # 提前返回的阻断结论同样持久化
                partial["blocked"] = True
                confirmed = self.confirm_validation(check_id, partial)
                return self._voucher_to_result(confirmed)

        final_result = {
            "passed": total_failed == 0,
            "checks": len(matching),
            "failed": total_failed,
            "passed_checks": total_passed,
            "details": results,
            "score": max(0, 100 - total_failed * 10),
        }
        confirmed = self.confirm_validation(check_id, final_result)
        return self._voucher_to_result(confirmed)

    def _voucher_to_result(self, voucher: dict[str, Any]) -> dict[str, Any]:
        """把持久化凭证还原为 validate_record 的返回结构。"""
        voucher = self._normalize_voucher(voucher)
        return {
            "passed": voucher.get("passed", voucher.get("outcome") == OUTCOME_PASSED),
            "checks": voucher.get("checks", 0),
            "failed": voucher.get("failed", 0),
            "passed_checks": voucher.get("passed_checks", 0),
            "details": voucher.get("details", []),
            "score": voucher.get("score", 0),
            "blocked": bool(voucher.get("blocked")),
            "check_id": voucher.get("id"),
            "检查编号": voucher.get("检查编号"),
            "cycle_id": voucher.get("cycle_id", ""),
            "credential_fingerprint": voucher.get("credential_fingerprint", ""),
            "status": voucher.get("status"),
            "outcome": voucher.get("outcome"),
            "confirmed_at": voucher.get("confirmed_at"),
        }

    def _execute_check(self, record: dict[str, Any], field: str, expression: str) -> dict[str, Any]:
        """执行校验表达式。

        支持的表达式操作：
        - "not_empty": 非空检查
        - "is_numeric": 是否为数字
        - "pattern:xxx": 正则匹配
        - "in:val1,val2": 值域检查
        - "len_gt:N": 长度大于N
        """
        value = record.get(field)
        field_present = field in record

        if expression == "not_empty":
            if not field_present or value is None or str(value).strip() == "":
                return {"passed": False, "message": f"字段 {field} 为空"}
            return {"passed": True, "message": "通过"}

        if expression == "is_numeric":
            try:
                float(str(value))
                return {"passed": True, "message": "通过"}
            except (ValueError, TypeError):
                return {"passed": False, "message": f"字段 {field} 不是数字"}

        if expression.startswith("pattern:"):
            pattern = expression.split(":", 1)[1]
            if not re.match(pattern, str(value)):
                return {"passed": False, "message": f"字段 {field} 不匹配模式 {pattern}"}
            return {"passed": True, "message": "通过"}

        if expression.startswith("in:"):
            allowed = expression.split(":", 1)[1].split(",")
            if str(value) not in allowed:
                return {"passed": False, "message": f"字段 {field} 不在允许值 {allowed} 中"}
            return {"passed": True, "message": "通过"}

        if expression.startswith("len_gt:"):
            min_len = int(expression.split(":", 1)[1])
            if len(str(value or "")) < min_len:
                return {"passed": False, "message": f"字段 {field} 长度小于 {min_len}"}
            return {"passed": True, "message": "通过"}

        return {"passed": True, "message": "未识别表达式，默认通过"}

    def _check_range(self, record: dict[str, Any], field: str, lower: float, upper: float) -> dict[str, Any]:
        """检查字段值是否在阈值范围内。"""
        if lower == 0 and upper == 0:
            return {"passed": True, "message": "无范围限制"}

        value = record.get(field)
        try:
            num_value = float(str(value))
        except (ValueError, TypeError):
            return {"passed": True, "message": "非数值字段跳过范围检查"}

        if lower > 0 and num_value < lower:
            return {"passed": False, "message": f"值 {num_value} 低于阈值 {lower}"}
        if upper > 0 and num_value > upper:
            return {"passed": False, "message": f"值 {num_value} 超过阈值 {upper}"}

        return {"passed": True, "message": f"值 {num_value} 在范围 [{lower}, {upper}] 内"}

    def validate_batch(self, records: list[dict[str, Any]], source_module: str = "",
                       cycle_id: str | None = None) -> dict[str, Any]:
        """批量质量校验：同一批次共享一个监控周期ID。"""
        cycle_id = cycle_id or f"cycle-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
        results = []
        passed_count = 0
        failed_count = 0
        blocked_count = 0

        for record in records:
            r = self.validate_record(record, source_module, cycle_id=cycle_id)
            if r.get("blocked"):
                blocked_count += 1
                failed_count += 1
            elif r["passed"]:
                passed_count += 1
            else:
                failed_count += 1
            results.append(r)

        avg_score = sum(r.get("score", 0) for r in results) / max(len(results), 1)

        return {
            "ok": blocked_count == 0,
            "total": len(records),
            "passed": passed_count,
            "failed": failed_count,
            "blocked": blocked_count,
            "average_score": round(avg_score, 2),
            "results": results,
            "cycle_id": cycle_id,
            "check_ids": [r.get("check_id") for r in results if r.get("check_id") is not None],
        }

    # ─────────────────────────────────────────────
    # 凭证查询与统计
    # ─────────────────────────────────────────────
    def list_vouchers(self, cycle_id: str | None = None,
                      status: str | None = None) -> list[dict[str, Any]]:
        """查询质量检查凭证，可按监控周期/状态过滤。"""
        rows = [self._normalize_voucher(r) for r in json_store.get_all(VOUCHER_KEY)]
        if cycle_id:
            rows = [r for r in rows if str(r.get("cycle_id", "")) == str(cycle_id)]
        if status:
            rows = [r for r in rows if r.get("status") == status]
        return sorted(rows, key=lambda r: r.get("started_at", ""), reverse=True)

    def get_voucher(self, check_id: int) -> dict[str, Any] | None:
        """按检查ID获取凭证（兼容历史凭证结构）。"""
        voucher = json_store.get_by_id(VOUCHER_KEY, check_id)
        return self._normalize_voucher(voucher) if voucher else None

    def get_voucher_by_fingerprint(self, fingerprint: str) -> dict[str, Any] | None:
        """按凭证指纹重新查询发布时的检查结论（重启后仍可查）。"""
        voucher = json_store.find_one(
            VOUCHER_KEY, lambda r: r.get("credential_fingerprint") == fingerprint
        )
        return self._normalize_voucher(voucher) if voucher else None

    def get_quality_report(self, cycle_id: str | None = None) -> dict[str, Any]:
        """获取质量校验报告。

        统计口径：只统计「已确认」凭证——仍在运行的检查既不计入通过，
        也不计入阻断；分母是已完成（已确认）的检查数。
        """
        vouchers = self.list_vouchers(cycle_id=cycle_id)
        confirmed = [v for v in vouchers if v.get("status") == STATUS_CONFIRMED]
        running = [v for v in vouchers if v.get("status") == STATUS_RUNNING]
        blocked = [v for v in confirmed if v.get("outcome") == OUTCOME_BLOCKED]
        failed = [
            v for v in confirmed
            if v.get("failed", 0) > 0 or v.get("outcome") in (OUTCOME_BLOCKED, OUTCOME_FAILED)
        ]
        passed = [v for v in confirmed if v.get("outcome") == OUTCOME_PASSED]

        rules = json_store.get_all(self.MODULE)
        active_rules = sum(1 for r in rules if r.get("status") == "已生效")
        completed = len(confirmed)
        block_rate = round(len(blocked) / completed, 4) if completed else 0.0
        pass_rate = round(len(passed) / completed, 4) if completed else 0.0

        return {
            "active_rules": active_rules,
            # 已完成检查数（统计分母），运行中的检查不纳入
            "total_checks": completed,
            "completed_checks": completed,
            "running_checks": len(running),
            "total_vouchers": len(vouchers),
            "passed_checks": len(passed),
            "recent_failures": len(failed),
            "recent_blocks": len(blocked),
            "block_rate": block_rate,
            "pass_rate": pass_rate,
            "cycle_id": cycle_id or "",
        }

    def domain_snapshot(self) -> dict[str, Any]:
        """输出接入质量校验的数据质量快照。"""
        rows = json_store.get_all(self.MODULE)
        by_status = {status: 0 for status in self.STATUS_ORDER}
        for row in rows:
            s = row.get("status", "")
            if s in by_status:
                by_status[s] += 1

        report = self.get_quality_report()
        return {
            "module": self.MODULE,
            "entity": self.ENTITY,
            "artifact": "接入质量校验数据集",
            "count": len(rows),
            "by_status": by_status,
            "abnormal": sum(1 for r in rows if r.get("abnormal")),
            "total_validations": report["total_vouchers"],
            "completed_validations": report["completed_checks"],
            "running_validations": report["running_checks"],
            "blocked_validations": report["recent_blocks"],
            "active_rules": sum(1 for r in rows if r.get("status") == "已生效"),
            "operation": self.OPERATION_TERM,
        }
