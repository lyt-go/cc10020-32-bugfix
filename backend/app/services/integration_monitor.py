"""集成监控看板领域服务：全局指标聚合、健康度评分与实时告警。

从各领域服务收集指标数据，聚合计算全局健康度评分、
成功率趋势和异常告警信息。
跨模块关联：call_trace_log（调用指标）、data_quality_rule（质量指标）、
data_lake_sink（落湖指标）、quality_review_ledger（质量复核台账）。

统计口径（修复点）
------------------
- 质量指标完全基于质检服务持久化的「质量检查凭证」计算：
  只有 status=已确认 的检查才进入分母；运行中的检查不算通过、
  也不算阻断，避免把尚未结束的检查统计成通过而掩盖阻断告警。
- 已发布的阻断率 = 已确认阻断凭证数 / 已确认凭证总数。
- 告警与检查结论同样持久化（``integration_monitor_alert`` 分区），
  服务重启后仍可查询；同一告警按指纹幂等，只发布一次。
- 质量阻断告警所依据的检查凭证会同步到质量复核台账。
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from app.persistence import json_store
from app.services.base import BaseModuleService

# 监控告警持久化分区
ALERT_KEY = "integration_monitor_alert"


class IntegrationMonitorService(BaseModuleService):
    MODULE = "integration_monitor"
    ENTITY = "监控指标"
    OPERATION_TERM = "查询"
    LIST_FIELDS = ["指标编号", "监控对象", "成功率", "平均延迟", "数据吞吐", "失败分类", "最近告警", "监控状态"]
    REQUIRED_FIELDS = ["指标编号", "监控对象", "成功率"]
    STATUS_ORDER = ["草稿", "待校验", "监控中", "已静默"]
    ACTION_RULES = {"提交校验": "待校验", "启动监控": "监控中", "静默告警": "已静默"}
    NEGATIVE_ACTIONS = []

    # ─────────────────────────────────────────────
    # 告警持久化（幂等发布）
    # ─────────────────────────────────────────────
    @staticmethod
    def _alert_fingerprint(alert: dict[str, Any]) -> str:
        raw = "|".join([
            str(alert.get("type", "")),
            str(alert.get("check_id", "")),
            str(alert.get("cycle_id", "")),
            str(alert.get("dedup_key", "")),
        ])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _publish_alert(self, alert: dict[str, Any]) -> dict[str, Any] | None:
        """幂等发布一条告警：同指纹告警只落库一次，返回 None 表示重复。"""
        alert = dict(alert)
        alert.setdefault("published_at", datetime.now(timezone.utc).isoformat())
        alert.setdefault("timestamp", alert["published_at"])
        alert["fingerprint"] = self._alert_fingerprint(alert)

        saved, inserted = json_store.insert_if_absent(
            ALERT_KEY,
            predicate=lambda r: r.get("fingerprint") == alert["fingerprint"],
            record=alert,
        )
        return saved if inserted else None

    def get_alerts(self, limit: int = 20, cycle_id: str | None = None) -> list[dict[str, Any]]:
        """获取告警历史（从持久化分区读取，重启不丢）。"""
        rows = json_store.get_all(ALERT_KEY)
        if cycle_id:
            rows = [r for r in rows if str(r.get("cycle_id", "")) == str(cycle_id)]
        return sorted(rows, key=lambda x: x.get("published_at", x.get("timestamp", "")),
                      reverse=True)[:limit]

    # ─────────────────────────────────────────────
    # 指标采集
    # ─────────────────────────────────────────────
    def collect_global_metrics(self, cycle_id: str | None = None) -> dict[str, Any]:
        """从所有领域服务收集全局监控指标。

        聚合维度：
        1. 调用链路：成功率、P95延迟、慢调用数
        2. 数据质量：已确认校验通过率、阻断率（运行中检查不纳入）
        3. 数据落湖：写入量、存储大小
        4. 增量水位：同步进度
        5. 死信队列：积压量、重放成功率
        6. 回补任务：完成率

        Returns:
            包含各维度指标和综合健康度评分的字典。
        """
        now = datetime.now(timezone.utc)
        metrics: dict[str, Any] = {
            "collected_at": now.isoformat(),
            "cycle_id": cycle_id or "",
            "modules": {},
        }

        # 调用链路指标 (call_trace_log)
        try:
            from app.services.call_trace_log import CallTraceLogService
            trace_svc = CallTraceLogService()
            perf = trace_svc.get_performance_stats(hours=24)
            metrics["trace"] = {
                "total_calls": perf.get("total", 0),
                "success_rate": perf.get("success_rate", 0),
                "avg_latency_ms": perf.get("avg_latency_ms", 0),
                "p95_ms": perf.get("p95_ms", 0),
            }
        except Exception as e:
            metrics["trace"] = {"error": str(e)}

        # 数据质量指标 (data_quality_rule)：只使用已确认凭证
        try:
            from app.services.data_quality_rule import DataQualityRuleService
            quality_svc = DataQualityRuleService()
            report = quality_svc.get_quality_report(cycle_id=cycle_id)
            metrics["quality"] = {
                "active_rules": report.get("active_rules", 0),
                # 分母：实际完成（已确认）的检查；运行中的检查单列
                "recent_checks": report.get("completed_checks", 0),
                "completed_checks": report.get("completed_checks", 0),
                "running_checks": report.get("running_checks", 0),
                "total_vouchers": report.get("total_vouchers", 0),
                "passed_checks": report.get("passed_checks", 0),
                "recent_failures": report.get("recent_failures", 0),
                "recent_blocks": report.get("recent_blocks", 0),
                "block_rate": report.get("block_rate", 0.0),
                "pass_rate": report.get("pass_rate", 0.0),
            }
        except Exception as e:
            metrics["quality"] = {"error": str(e)}

        # 数据落湖指标 (data_lake_sink)
        try:
            from app.services.data_lake_sink import DataLakeSinkService
            sink_svc = DataLakeSinkService()
            lake_stats = sink_svc.get_lake_stats()
            metrics["lake"] = {
                "total_files": lake_stats.get("total_files", 0),
                "total_size_mb": lake_stats.get("total_size_mb", 0),
            }
        except Exception as e:
            metrics["lake"] = {"error": str(e)}

        # 死信队列指标 (dlq_handler)
        try:
            from app.services.dlq_handler import DlqHandlerService
            dlq_svc = DlqHandlerService()
            dlq_stats = dlq_svc.get_dlq_stats()
            metrics["dlq"] = {
                "total_dlq": dlq_stats.get("total_dlq", 0),
                "pending": dlq_stats.get("pending_dispatch", 0),
                "replayed": dlq_stats.get("replayed_count", 0),
            }
        except Exception as e:
            metrics["dlq"] = {"error": str(e)}

        # 增量水位指标 (incre_cursor)
        try:
            from app.services.incre_cursor import IncreCursorService
            cursor_svc = IncreCursorService()
            positions = cursor_svc.get_all_positions()
            metrics["cursors"] = {
                "active_cursors": len(positions),
                "total_position": sum(positions.values()) if positions else 0,
            }
        except Exception as e:
            metrics["cursors"] = {"error": str(e)}

        # 批量接入指标 (batch_ingest)
        try:
            rows = json_store.get_all("batch_ingest")
            metrics["batch"] = {
                "total_tasks": len(rows),
                "running_tasks": sum(1 for r in rows if r.get("status") == "运行中"),
            }
        except Exception as e:
            metrics["batch"] = {"error": str(e)}

        # 计算综合健康度
        health = self._calculate_health_score(metrics)
        metrics["health_score"] = health["score"]
        metrics["health_status"] = health["status"]
        metrics["health_issues"] = health["issues"]

        # 触发告警检查（幂等持久化 + 台账同步）
        alerts = self._check_alerts(metrics, cycle_id=cycle_id)
        metrics["alerts"] = alerts

        return metrics

    def _calculate_health_score(self, metrics: dict[str, Any]) -> dict[str, Any]:
        """计算综合健康度评分（0-100）。"""
        score = 100.0
        issues = []

        # 调用成功率扣分：无调用数据（total=0）时不按 0% 成功率扣分
        trace_data = metrics.get("trace", {})
        if (isinstance(trace_data, dict)
                and "success_rate" in trace_data
                and trace_data.get("total_calls", 0) > 0):
            success_rate = trace_data["success_rate"]
            if success_rate < 95:
                deduction = (95 - success_rate) * 2
                score -= deduction
                issues.append(f"调用成功率 {success_rate}% 低于95% (扣{deduction:.0f}分)")

        # 死信积压扣分
        dlq_data = metrics.get("dlq", {})
        if isinstance(dlq_data, dict) and "pending" in dlq_data:
            pending = dlq_data["pending"]
            if pending > 10:
                score -= min(pending, 20)
                issues.append(f"死信积压 {pending} 条")

        # 质量失败扣分：只按已确认的失败/阻断凭证计算
        quality_data = metrics.get("quality", {})
        if isinstance(quality_data, dict) and "recent_failures" in quality_data:
            failures = quality_data["recent_failures"]
            if failures > 5:
                score -= min(failures * 2, 15)
                issues.append(f"质量校验失败 {failures} 次")
            block_rate = quality_data.get("block_rate", 0.0)
            if block_rate > 0:
                score -= min(block_rate * 100, 20)
                issues.append(f"已发布质量阻断率 {block_rate:.2%}")

        score = max(0.0, min(100.0, score))

        status = "健康"
        if score < 60:
            status = "严重"
        elif score < 80:
            status = "警告"

        return {"score": round(score, 2), "status": status, "issues": issues}

    def _check_alerts(self, metrics: dict[str, Any],
                      cycle_id: str | None = None) -> list[dict[str, Any]]:
        """检查是否触发告警条件；新告警幂等落库并同步复核台账。"""
        alerts: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()
        trace_data = metrics.get("trace", {})

        # 成功率告警
        if isinstance(trace_data, dict) and trace_data.get("success_rate", 100) < 90:
            alert = {
                "level": "critical",
                "type": "low_success_rate",
                "message": f"调用成功率降至 {trace_data['success_rate']}%",
                "dedup_key": f"{trace_data['success_rate']}",
                "cycle_id": cycle_id or "",
            }
            published = self._publish_alert(alert)
            if published:
                alerts.append(published)

        # 死信积压告警
        dlq_data = metrics.get("dlq", {})
        if isinstance(dlq_data, dict) and dlq_data.get("pending", 0) > 20:
            alert = {
                "level": "warning",
                "type": "dead_letter_backlog",
                "message": f"死信积压 {dlq_data['pending']} 条",
                "dedup_key": str(dlq_data["pending"]),
                "cycle_id": cycle_id or "",
            }
            published = self._publish_alert(alert)
            if published:
                alerts.append(published)

        # P95延迟告警
        if isinstance(trace_data, dict) and trace_data.get("p95_ms", 0) > 5000:
            alert = {
                "level": "warning",
                "type": "high_latency",
                "message": f"P95延迟 {trace_data['p95_ms']}ms 超过5000ms阈值",
                "dedup_key": str(trace_data["p95_ms"]),
                "cycle_id": cycle_id or "",
            }
            published = self._publish_alert(alert)
            if published:
                alerts.append(published)

        # 质量阻断告警：每一条已确认阻断凭证对应一条告警，并同步复核台账
        quality_data = metrics.get("quality", {})
        if isinstance(quality_data, dict) and quality_data.get("recent_blocks", 0) > 0:
            alerts.extend(self._publish_quality_block_alerts(
                block_rate=quality_data.get("block_rate", 0.0),
                denominator=quality_data.get("completed_checks", 0),
                cycle_id=cycle_id,
                now=now,
            ))

        return alerts

    def _publish_quality_block_alerts(self, block_rate: float, denominator: int,
                                      cycle_id: str | None, now: str) -> list[dict[str, Any]]:
        """为已确认的阻断检查凭证发布告警并同步复核台账。"""
        from app.services.data_quality_rule import (
            VOUCHER_KEY,
            DataQualityRuleService,
            OUTCOME_BLOCKED,
            STATUS_CONFIRMED,
        )
        from app.services.quality_review_ledger import QualityReviewLedgerService

        published_alerts: list[dict[str, Any]] = []
        ledger_svc = QualityReviewLedgerService()
        vouchers = json_store.get_all(VOUCHER_KEY)
        for raw in vouchers:
            voucher = DataQualityRuleService._normalize_voucher(raw)
            if voucher.get("status") != STATUS_CONFIRMED:
                continue
            if voucher.get("outcome") != OUTCOME_BLOCKED:
                continue
            if cycle_id and str(voucher.get("cycle_id", "")) != str(cycle_id):
                continue

            alert = {
                "level": "critical",
                "type": "quality_check_blocked",
                "message": (
                    f"质量检查 {voucher.get('检查编号')} 确认阻断"
                    f"（本轮已确认 {denominator} 次，阻断率 {block_rate:.2%}）"
                ),
                "check_id": voucher.get("id"),
                "检查编号": voucher.get("检查编号"),
                "cycle_id": voucher.get("cycle_id", cycle_id or ""),
                "block_rate": block_rate,
                "denominator": denominator,
                "credential_fingerprint": voucher.get("credential_fingerprint", ""),
                "rule_digest": voucher.get("rule_digest", ""),
                "published_at": now,
            }
            published = self._publish_alert(alert)
            if published is None:
                continue  # 告警已发布过，台账也已同步，跳过
            # 将告警对应的检查结果同步到复核台账（幂等）
            ledger_svc.sync_alert(published, voucher)
            published_alerts.append(published)
        return published_alerts

    def get_health_status(self) -> dict[str, Any]:
        """获取当前健康状态。"""
        metrics = self.collect_global_metrics()
        return {
            "health_score": metrics.get("health_score", 0),
            "health_status": metrics.get("health_status", "未知"),
            "issues": metrics.get("health_issues", []),
            "alerts_count": len(metrics.get("alerts", [])),
            "collected_at": metrics.get("collected_at"),
        }

    def get_quality_monitor_overview(self, cycle_id: str | None = None) -> dict[str, Any]:
        """值班监控视图：按监控周期核对告警、复核记录与检查口径。

        展示内容：
        - 本轮用来判定告警的已确认数据（阻断凭证、阻断率、健康分）；
        - 分母范围：已确认检查数（运行中的检查不计入）；
        - 仍在执行的检查清单；
        - 阻断告警及其对应的复核台账记录。
        """
        from app.services.data_quality_rule import (
            VOUCHER_KEY,
            DataQualityRuleService,
            OUTCOME_BLOCKED,
            STATUS_CONFIRMED,
            STATUS_RUNNING,
        )
        from app.services.quality_review_ledger import QualityReviewLedgerService

        metrics = self.collect_global_metrics(cycle_id=cycle_id)
        quality = metrics.get("quality", {})

        all_vouchers = [
            DataQualityRuleService._normalize_voucher(r)
            for r in json_store.get_all(VOUCHER_KEY)
        ]
        if cycle_id:
            all_vouchers = [v for v in all_vouchers if str(v.get("cycle_id", "")) == str(cycle_id)]

        confirmed = [v for v in all_vouchers if v.get("status") == STATUS_CONFIRMED]
        running = [v for v in all_vouchers if v.get("status") == STATUS_RUNNING]
        blocked_vouchers = [v for v in confirmed if v.get("outcome") == OUTCOME_BLOCKED]

        alerts = self.get_alerts(limit=100, cycle_id=cycle_id)
        block_alerts = [a for a in alerts if a.get("type") == "quality_check_blocked"]

        ledger_svc = QualityReviewLedgerService()
        review_rows = ledger_svc.list_entries_for_cycle(cycle_id)

        return {
            "cycle_id": cycle_id or "",
            "collected_at": metrics.get("collected_at"),
            "health_score": metrics.get("health_score", 0),
            "health_status": metrics.get("health_status", "未知"),
            "quality": {
                # 分母：实际完成的检查
                "denominator": quality.get("completed_checks", 0),
                "completed_checks": quality.get("completed_checks", 0),
                "running_checks": quality.get("running_checks", 0),
                "passed_checks": quality.get("passed_checks", 0),
                "blocked_checks": quality.get("recent_blocks", 0),
                # 已发布的阻断率
                "block_rate": quality.get("block_rate", 0.0),
                "pass_rate": quality.get("pass_rate", 0.0),
            },
            # 用来判定告警的已确认数据
            "confirmed_blocked_vouchers": [
                {
                    "check_id": v.get("id"),
                    "检查编号": v.get("检查编号"),
                    "outcome": v.get("outcome"),
                    "confirmed_at": v.get("confirmed_at"),
                    "credential_fingerprint": v.get("credential_fingerprint"),
                    "rule_digest": v.get("rule_digest"),
                }
                for v in blocked_vouchers
            ],
            # 仍在执行、尚不能计入统计的检查
            "running_vouchers": [
                {
                    "check_id": v.get("id"),
                    "检查编号": v.get("检查编号"),
                    "started_at": v.get("started_at"),
                    "retries": v.get("retries", 0),
                }
                for v in running
            ],
            "block_alerts": block_alerts,
            # 告警对应的复核台账记录
            "review_ledger": review_rows,
            "alerts_total": len(alerts),
        }

    def domain_snapshot(self) -> dict[str, Any]:
        """输出集成监控看板的数据质量快照。"""
        rows = json_store.get_all(self.MODULE)
        by_status = {status: 0 for status in self.STATUS_ORDER}
        for row in rows:
            s = row.get("status", "")
            if s in by_status:
                by_status[s] += 1

        health = self.get_health_status()
        return {
            "module": self.MODULE,
            "entity": self.ENTITY,
            "artifact": "集成监控看板数据集",
            "count": len(rows),
            "by_status": by_status,
            "abnormal": sum(1 for r in rows if r.get("abnormal")),
            "health_score": health.get("health_score", 0),
            "health_status": health.get("health_status", "未知"),
            "alerts_total": len(json_store.get_all(ALERT_KEY)),
            "operation": self.OPERATION_TERM,
        }
