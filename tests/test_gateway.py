"""
Gateway authorization tests - no model required. These prove the security
property the whole project rests on: whatever the (possibly injected) agent asks
for, the hardened gateway never executes a restricted action.

    python -m unittest discover -s tests -v
"""

import unittest

from app.gateway import Gateway
from app.tools import AGENT_CANARY


class TestInsecure(unittest.TestCase):
    def test_restricted_executes(self):
        gw = Gateway(defended=False)
        call = gw.execute("query_inventory", {"asset_id": "RESTRICTED-ASSET-9"})
        self.assertTrue(call.allowed)
        self.assertIn(AGENT_CANARY, call.result)
        self.assertTrue(gw.restricted_was_accessed())


class TestHardened(unittest.TestCase):
    def test_query_inventory_blocked_by_allowlist(self):
        gw = Gateway(defended=True)  # default allow-list excludes query_inventory
        call = gw.execute("query_inventory", {"asset_id": "RESTRICTED-ASSET-9"})
        self.assertFalse(call.allowed)
        self.assertEqual(call.reason, "not_in_task_allowlist")
        self.assertFalse(gw.restricted_was_accessed())

    def test_high_impact_needs_approval(self):
        gw = Gateway(defended=True, allowed_tools={"query_inventory"})
        call = gw.execute("query_inventory", {"asset_id": "LAPTOP-204"})
        self.assertFalse(call.allowed)
        self.assertEqual(call.reason, "high_impact_needs_approval")

    def test_restricted_resource_blocked_even_when_approved(self):
        gw = Gateway(defended=True, allowed_tools={"query_inventory"},
                     approved_high_impact={"query_inventory"})
        call = gw.execute("query_inventory", {"asset_id": "RESTRICTED-ASSET-9"})
        self.assertFalse(call.allowed)
        self.assertEqual(call.reason, "restricted_resource")

    def test_non_restricted_allowed_when_approved(self):
        gw = Gateway(defended=True, allowed_tools={"query_inventory"},
                     approved_high_impact={"query_inventory"})
        call = gw.execute("query_inventory", {"asset_id": "LAPTOP-204"})
        self.assertTrue(call.allowed)

    def test_low_impact_tools_allowed(self):
        gw = Gateway(defended=True)
        self.assertTrue(gw.execute("read_docs", {"doc_id": "wifi-setup"}).allowed)
        self.assertTrue(gw.execute("create_ticket", {"summary": "x"}).allowed)


if __name__ == "__main__":
    unittest.main()
