"""质量校验凭证持久化与监控统计修复的端到端测试。

覆盖题述场景：
1. 通过与提前返回的阻断检查结果都持久化，重启后仍可按凭证查询；
2. 兼容历史凭证结构（旧布尔/旧 outcome 字段）；
3. 并发重试同一次校验只确认一份有效结论；
4. 告警统计只按实际完成（已确认）的检查计算，运行中检查不算通过；
5. 集成监控基于凭证计算已发布阻断率与健康分，阻断告警同步复核台账；
6. 同一监控周期两条检查：先启动的运行中、后启动的已阻断，
   值班员刷新监控能看到阻断告警、复核记录、分母与运行中检查；
7. 第一条完成后再次统计并重启，历史结论按发布时凭证可重新查到。
"""
from __future__ import annotations

import os
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.persistence import JsonStore, json_store as global_store
from app.services.data_quality_rule import (
    VOUCHER_KEY,
    DataQualityRuleService,
    OUTCOME_BLOCKED,
    OUTCOME_PASSED,
    STATUS_CONFIRMED,
    STATUS_RUNNING,
)
from app.services.integration_monitor import ALERT_KEY, IntegrationMonitorService
from app.services.quality_review_ledger import LEDGER_KEY, QualityReviewLedgerService


class QualityVoucherTestBase(unittest.TestCase):
    """每个用例使用独立临时存储目录，模拟干净的实例环境。"""

    # 这些模块在导入时绑定 json_store，需要逐一切换引用
    _STORE_BINDING_MODULES = [
        "app.persistence",
        "app.services.data_quality_rule",
        "app.services.integration_monitor",
        "app.services.quality_review_ledger",
        "app.services.data_lake_sink",
        "app.services.dlq_handler",
        "app.services.call_trace_log",
        "app.services.incre_cursor",
    ]

    def setUp(self) -> None:
        import importlib
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.store = JsonStore(base_dir=self._tmp.name)
        import app.persistence
        self._original_store = app.persistence.json_store

        self._patched = []
        for name in self._STORE_BINDING_MODULES:
            module = importlib.import_module(name)
            if hasattr(module, "json_store"):
                self._patched.append((module, module.json_store))
                module.json_store = self.store

        self.quality_svc = DataQualityRuleService()
        self.monitor_svc = IntegrationMonitorService()
        self.ledger_svc = QualityReviewLedgerService()

        # 一条警告规则 + 一条阻断规则
        self.store.insert("data_quality_rule", {
            "规则编号": "QUAL-WARN-001",
            "数据来源": "ALL",
            "校验字段": "name",
            "校验表达式": "not_empty",
            "阈值下界": "0",
            "阈值上界": "0",
            "阻断策略": "警告",
            "规则版本": "v1",
            "status": "已生效",
        })
        self.store.insert("data_quality_rule", {
            "规则编号": "QUAL-BLOCK-001",
            "数据来源": "ALL",
            "校验字段": "amount",
            "校验表达式": "is_numeric",
            "阈值下界": "10",
            "阈值上界": "1000",
            "阻断策略": "阻断",
            "规则版本": "v1",
            "status": "已生效",
        })

    def tearDown(self) -> None:
        for module, original in self._patched:
            module.json_store = original
        self._tmp.cleanup()


class TestVoucherPersistence(QualityVoucherTestBase):
    """通过与阻断结论均持久化、重启可查。"""

    def test_passed_result_is_persisted(self):
        result = self.quality_svc.validate_record(
            {"name": "正常记录", "amount": 100}, source_module="test"
        )
        self.assertTrue(result["passed"])
        self.assertFalse(result["blocked"])
        self.assertIsNotNone(result["check_id"])

        voucher = self.quality_svc.get_voucher(result["check_id"])
        self.assertEqual(voucher["status"], STATUS_CONFIRMED)
        self.assertEqual(voucher["outcome"], OUTCOME_PASSED)
        self.assertTrue(voucher["credential_fingerprint"])

    def test_blocked_early_return_is_persisted(self):
        # amount 低于阈值下界，命中阻断规则后提前返回
        result = self.quality_svc.validate_record(
            {"name": "问题记录", "amount": 1}, source_module="test"
        )
        self.assertTrue(result["blocked"])
        self.assertFalse(result["passed"])

        # 阻断结论同样落库，而不是只留在进程内存
        voucher = self.quality_svc.get_voucher(result["check_id"])
        self.assertEqual(voucher["status"], STATUS_CONFIRMED)
        self.assertEqual(voucher["outcome"], OUTCOME_BLOCKED)
        self.assertTrue(voucher["blocked"])
        self.assertTrue(voucher["credential_fingerprint"])
        self.assertGreaterEqual(len(voucher["details"]), 1)

    def test_voucher_survives_service_restart(self):
        result = self.quality_svc.validate_record(
            {"name": "重启前记录", "amount": 500}, source_module="test"
        )
        check_id = result["check_id"]
        fingerprint = result["credential_fingerprint"]

        # 模拟服务重启：新建服务实例（存储在磁盘上，不依赖内存态）
        restarted_svc = DataQualityRuleService()
        voucher = restarted_svc.get_voucher(check_id)
        self.assertIsNotNone(voucher)
        self.assertEqual(voucher["status"], STATUS_CONFIRMED)

        # 按发布时的凭证指纹重新查到同一份结论
        by_fp = restarted_svc.get_voucher_by_fingerprint(fingerprint)
        self.assertIsNotNone(by_fp)
        self.assertEqual(by_fp["id"], check_id)

    def test_legacy_voucher_is_normalized(self):
        """历史凭证（旧布尔/outcome 形态）读取时被兼容归一化。"""
        self.store.insert(VOUCHER_KEY, {
            "检查编号": "QC-LEGACY-001",
            # 旧数据没有统一 status，只有 passed/blocked 布尔
            "passed": False,
            "blocked": True,
            "outcome": "blocked",
            "checks": 2,
            "failed": 1,
            "details": [],
            "cycle_id": "legacy-cycle",
            "confirmed_at": "2026-11-01T00:00:00+00:00",
        })
        self.store.insert(VOUCHER_KEY, {
            "检查编号": "QC-LEGACY-002",
            # 更老的形态：仅 passed 布尔、无 outcome
            "passed": True,
            "checks": 1,
            "failed": 0,
            "cycle_id": "legacy-cycle",
        })

        vouchers = self.quality_svc.list_vouchers(cycle_id="legacy-cycle")
        by_no = {v["检查编号"]: v for v in vouchers}
        self.assertEqual(by_no["QC-LEGACY-001"]["status"], STATUS_CONFIRMED)
        self.assertEqual(by_no["QC-LEGACY-001"]["outcome"], OUTCOME_BLOCKED)
        self.assertEqual(by_no["QC-LEGACY-002"]["status"], STATUS_CONFIRMED)
        self.assertEqual(by_no["QC-LEGACY-002"]["outcome"], OUTCOME_PASSED)

        # 历史阻断凭证必须能被监控统计识别
        report = self.quality_svc.get_quality_report(cycle_id="legacy-cycle")
        self.assertEqual(report["completed_checks"], 2)
        self.assertEqual(report["recent_blocks"], 1)


class TestConcurrentConfirmation(QualityVoucherTestBase):
    """并发重试同一次校验只确认一份有效结论。"""

    def test_concurrent_start_returns_single_running_voucher(self):
        record = {"name": "并发记录", "amount": 200}
        cycle = "cycle-concurrent-1"
        vouchers = []

        def start():
            vouchers.append(
                self.quality_svc.start_validation(record, "test", cycle_id=cycle)
            )

        threads = [threading.Thread(target=start) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        ids = {v["id"] for v in vouchers}
        self.assertEqual(len(ids), 1, "同一次校验并发启动只能产生一份凭证")
        only = vouchers[0]
        self.assertEqual(only["status"], STATUS_RUNNING)
        # 重试次数被累计
        refreshed = self.quality_svc.get_voucher(only["id"])
        self.assertGreaterEqual(refreshed.get("retries", 0), 1)

    def test_concurrent_confirm_publishes_one_conclusion(self):
        voucher = self.quality_svc.start_validation(
            {"name": "并发确认", "amount": 200}, "test", cycle_id="cycle-concurrent-2"
        )
        check_id = voucher["id"]
        outcomes: list[dict] = []

        def confirm():
            outcomes.append(self.quality_svc.confirm_validation(check_id, {
                "passed": True, "blocked": False, "failed": 0,
                "passed_checks": 2, "checks": 2, "score": 100, "details": [],
            }))

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: confirm(), range(8)))

        self.assertEqual(len(outcomes), 8)
        fingerprints = {o["credential_fingerprint"] for o in outcomes}
        self.assertEqual(len(fingerprints), 1, "只允许一份有效确认结论")
        self.assertTrue(all(o["status"] == STATUS_CONFIRMED for o in outcomes))

        # 已确认后再次启动同一校验，直接复用有效结论
        again = self.quality_svc.start_validation(
            {"name": "并发确认", "amount": 200}, "test", cycle_id="cycle-concurrent-2"
        )
        self.assertEqual(again["status"], STATUS_CONFIRMED)
        self.assertEqual(again["id"], check_id)

    def test_validate_record_retry_is_idempotent(self):
        record = {"name": "幂等记录", "amount": 200}
        r1 = self.quality_svc.validate_record(record, "test", cycle_id="cycle-idem")
        r2 = self.quality_svc.validate_record(record, "test", cycle_id="cycle-idem")
        self.assertEqual(r1["check_id"], r2["check_id"])
        self.assertEqual(r1["credential_fingerprint"], r2["credential_fingerprint"])
        self.assertEqual(len(self.store.get_all(VOUCHER_KEY)), 1)


class TestMonitorStatistics(QualityVoucherTestBase):
    """统计口径：运行中检查不算通过；阻断率与健康分按凭证计算。"""

    def test_running_check_not_counted_as_passed(self):
        # 先启动一条检查但不确认（仍在运行）
        running = self.quality_svc.start_validation(
            {"name": "运行中", "amount": 200}, "test", cycle_id="cycle-stats"
        )
        self.assertEqual(running["status"], STATUS_RUNNING)

        report = self.quality_svc.get_quality_report(cycle_id="cycle-stats")
        self.assertEqual(report["running_checks"], 1)
        self.assertEqual(report["completed_checks"], 0)
        # 尚未结束的检查不能算为通过
        self.assertEqual(report["passed_checks"], 0)
        self.assertEqual(report["block_rate"], 0.0)

        metrics = self.monitor_svc.collect_global_metrics(cycle_id="cycle-stats")
        self.assertEqual(metrics["quality"]["running_checks"], 1)
        self.assertEqual(metrics["quality"]["completed_checks"], 0)

    def test_block_rate_and_alert_and_ledger(self):
        cycle = "cycle-block"
        # 一条通过
        self.quality_svc.validate_record(
            {"name": "通过", "amount": 100}, "test", cycle_id=cycle
        )
        # 一条阻断（提前返回）
        blocked = self.quality_svc.validate_record(
            {"name": "阻断", "amount": 1}, "test", cycle_id=cycle
        )
        self.assertTrue(blocked["blocked"])

        report = self.quality_svc.get_quality_report(cycle_id=cycle)
        self.assertEqual(report["completed_checks"], 2)
        self.assertEqual(report["recent_blocks"], 1)
        self.assertEqual(report["block_rate"], 0.5)

        # 监控发布阻断告警并同步复核台账
        metrics = self.monitor_svc.collect_global_metrics(cycle_id=cycle)
        self.assertEqual(metrics["quality"]["recent_blocks"], 1)
        self.assertEqual(metrics["quality"]["block_rate"], 0.5)

        alerts = self.monitor_svc.get_alerts(cycle_id=cycle)
        block_alerts = [a for a in alerts if a["type"] == "quality_check_blocked"]
        self.assertEqual(len(block_alerts), 1)
        alert = block_alerts[0]
        self.assertEqual(alert["check_id"], blocked["check_id"])
        self.assertEqual(alert["denominator"], 2)

        ledger_rows = self.ledger_svc.list_entries_for_cycle(cycle)
        self.assertEqual(len(ledger_rows), 1)
        self.assertEqual(ledger_rows[0]["检查ID"], blocked["check_id"])
        self.assertTrue(ledger_rows[0]["阻断"])
        self.assertEqual(ledger_rows[0]["凭证指纹"], blocked["credential_fingerprint"])

        # 重复采集不重复发布告警、不重复写台账
        self.monitor_svc.collect_global_metrics(cycle_id=cycle)
        self.monitor_svc.collect_global_metrics(cycle_id=cycle)
        self.assertEqual(
            len([a for a in self.monitor_svc.get_alerts(cycle_id=cycle)
                 if a["type"] == "quality_check_blocked"]),
            1,
        )
        self.assertEqual(len(self.ledger_svc.list_entries_for_cycle(cycle)), 1)

        # 告警本身也持久化，重启可查
        restarted_monitor = IntegrationMonitorService()
        self.assertEqual(
            len([a for a in restarted_monitor.get_alerts(cycle_id=cycle)
                 if a["type"] == "quality_check_blocked"]),
            1,
        )


class TestDutyOfficerScenario(QualityVoucherTestBase):
    """题述值班员全流程场景。"""

    def test_full_duty_scenario(self):
        cycle = "cycle-duty-20261120"

        # 同周期两条检查：第一条先启动且保持运行
        first = self.quality_svc.start_validation(
            {"name": "第一条", "amount": 100}, "test", cycle_id=cycle
        )
        self.assertEqual(first["status"], STATUS_RUNNING)

        # 第二条启动后立即确认阻断
        second = self.quality_svc.start_validation(
            {"name": "第二条", "amount": 5}, "test", cycle_id=cycle
        )
        blocked_voucher = self.quality_svc.confirm_validation(second["id"], {
            "passed": False, "blocked": True, "failed": 1,
            "passed_checks": 0, "checks": 2, "score": 90,
            "details": [{"rule_no": "QUAL-BLOCK-001", "passed": False}],
        })
        self.assertEqual(blocked_voucher["outcome"], OUTCOME_BLOCKED)

        # 值班员刷新监控
        overview = self.monitor_svc.get_quality_monitor_overview(cycle_id=cycle)

        # 已有阻断告警 + 对应复核记录
        self.assertEqual(len(overview["block_alerts"]), 1)
        self.assertEqual(overview["block_alerts"][0]["check_id"], second["id"])
        self.assertEqual(len(overview["review_ledger"]), 1)
        self.assertEqual(overview["review_ledger"][0]["检查ID"], second["id"])

        # 分母只含已确认检查（1 条），运行中的第一条不纳入
        self.assertEqual(overview["quality"]["denominator"], 1)
        self.assertEqual(overview["quality"]["completed_checks"], 1)
        self.assertEqual(overview["quality"]["blocked_checks"], 1)
        self.assertEqual(overview["quality"]["block_rate"], 1.0)
        self.assertEqual(overview["quality"]["running_checks"], 1)

        # 仍在执行的检查可核对
        self.assertEqual(len(overview["running_vouchers"]), 1)
        self.assertEqual(overview["running_vouchers"][0]["check_id"], first["id"])

        # 用来判定告警的已确认数据可核对
        self.assertEqual(len(overview["confirmed_blocked_vouchers"]), 1)
        self.assertEqual(
            overview["confirmed_blocked_vouchers"][0]["credential_fingerprint"],
            blocked_voucher["credential_fingerprint"],
        )

        # 第一条检查完成（通过）
        first_done = self.quality_svc.confirm_validation(first["id"], {
            "passed": True, "blocked": False, "failed": 0,
            "passed_checks": 2, "checks": 2, "score": 100, "details": [],
        })
        self.assertEqual(first_done["outcome"], OUTCOME_PASSED)

        # 再次统计：分母变为 2，阻断率 50%；阻断告警不重复发布
        overview2 = self.monitor_svc.get_quality_monitor_overview(cycle_id=cycle)
        self.assertEqual(overview2["quality"]["denominator"], 2)
        self.assertEqual(overview2["quality"]["block_rate"], 0.5)
        self.assertEqual(overview2["quality"]["running_checks"], 0)
        self.assertEqual(len(overview2["block_alerts"]), 1)
        self.assertEqual(len(overview2["review_ledger"]), 1)
        self.assertGreater(overview2["health_score"], 0)

        # 服务重启：历史结论按发布时凭证重新查到，告警与台账仍在
        restarted_quality = DataQualityRuleService()
        restarted_monitor = IntegrationMonitorService()
        restarted_ledger = QualityReviewLedgerService()

        for voucher_id, expected_fp in (
            (first["id"], first_done["credential_fingerprint"]),
            (second["id"], blocked_voucher["credential_fingerprint"]),
        ):
            reloaded = restarted_quality.get_voucher(voucher_id)
            self.assertIsNotNone(reloaded)
            self.assertEqual(reloaded["status"], STATUS_CONFIRMED)
            self.assertEqual(
                restarted_quality.get_voucher_by_fingerprint(expected_fp)["id"],
                voucher_id,
            )

        after_restart = restarted_monitor.get_quality_monitor_overview(cycle_id=cycle)
        self.assertEqual(after_restart["quality"]["denominator"], 2)
        self.assertEqual(after_restart["quality"]["block_rate"], 0.5)
        self.assertEqual(len(after_restart["block_alerts"]), 1)
        self.assertEqual(len(after_restart["review_ledger"]), 1)
        self.assertEqual(len(restarted_ledger.list_entries_for_cycle(cycle)), 1)

    def test_alert_persistence_rows_are_on_disk(self):
        """确认告警与台账写入的是 json_store 分区而非实例内存。"""
        cycle = "cycle-disk"
        self.quality_svc.validate_record(
            {"name": "阻断", "amount": 1}, "test", cycle_id=cycle
        )
        self.monitor_svc.collect_global_metrics(cycle_id=cycle)
        self.assertGreaterEqual(len(self.store.get_all(ALERT_KEY)), 1)
        self.assertGreaterEqual(len(self.store.get_all(LEDGER_KEY)), 1)
        # 全新实例（模拟重启）仍能读到
        self.assertGreaterEqual(
            len(IntegrationMonitorService().get_alerts(cycle_id=cycle)), 1
        )


class TestBatchValidation(QualityVoucherTestBase):
    """批量校验共享监控周期并全部持久化。"""

    def test_batch_persists_all_vouchers_with_cycle(self):
        result = self.quality_svc.validate_batch(
            records=[
                {"name": "A", "amount": 100},
                {"name": "B", "amount": 1},   # 阻断
                {"name": "", "amount": 200},  # 警告失败但不阻断
            ],
            source_module="test",
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["blocked"], 1)
        self.assertEqual(len(result["check_ids"]), 3)
        cycle = result["cycle_id"]

        vouchers = self.quality_svc.list_vouchers(cycle_id=cycle)
        self.assertEqual(len(vouchers), 3)
        self.assertTrue(all(v["status"] == STATUS_CONFIRMED for v in vouchers))

        report = self.quality_svc.get_quality_report(cycle_id=cycle)
        self.assertEqual(report["completed_checks"], 3)
        self.assertEqual(report["recent_blocks"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
