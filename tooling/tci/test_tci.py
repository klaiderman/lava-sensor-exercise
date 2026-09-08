import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_registry
import tci


THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REAL_REGISTRY_PATH = os.path.join(THIS_DIR, "probes.json")


def probe(id, cmd, timeout_s=5, cap_bytes=1024, priority=50, requires=None,
          sensitivity="low", facts=None, group="g"):
    return {
        "id": id, "group": group, "cmd": cmd, "timeout_s": timeout_s,
        "cap_bytes": cap_bytes, "priority": priority,
        "requires": requires or [], "sensitivity": sensitivity,
        "facts": facts or [],
    }


def ev(pid, status, rc=0, stdout="", truncated=False):
    return {"id": pid, "status": status, "rc": rc, "stdout": stdout,
            "truncated": truncated, "duration_hint": None,
            "classified_from": "test"}


# --------------------------------------------------------------------------
# Registry validator
# --------------------------------------------------------------------------
class TestRegistryValidator(unittest.TestCase):
    def base_registry(self, cmd="cat /etc/os-release"):
        return {"version": 1, "probes": [
            probe("os.release", cmd),
        ]}

    def test_rejects_sudo(self):
        reg = self.base_registry("sudo cat /etc/shadow")
        ok, errors = check_registry.validate_registry(reg)
        self.assertFalse(ok)
        self.assertTrue(any("sudo" in e for e in errors))

    def test_rejects_rm_rf(self):
        reg = self.base_registry("rm -rf /tmp/x")
        ok, errors = check_registry.validate_registry(reg)
        self.assertFalse(ok)
        self.assertTrue(any("rm" in e for e in errors))

    def test_rejects_redirection(self):
        reg = self.base_registry("cat /etc/hosts > /tmp/out")
        ok, errors = check_registry.validate_registry(reg)
        self.assertFalse(ok)
        self.assertTrue(any("redirection" in e for e in errors))

    def test_allows_redirection_exceptions(self):
        reg = self.base_registry("cat /etc/hosts 2>&1 </dev/null")
        ok, errors = check_registry.validate_registry(reg)
        self.assertTrue(ok, errors)

    def test_rejects_duplicate_id(self):
        reg = {"version": 1, "probes": [
            probe("a.one", "cat /etc/hosts"),
            probe("a.one", "cat /etc/hostname"),
        ]}
        ok, errors = check_registry.validate_registry(reg)
        self.assertFalse(ok)
        self.assertTrue(any("duplicate id" in e for e in errors))

    def test_rejects_dangling_requires(self):
        reg = {"version": 1, "probes": [
            probe("a.one", "cat /etc/hosts",
                  requires=[{"fact": "nonexistent_fact", "eq": True}]),
        ]}
        ok, errors = check_registry.validate_registry(reg)
        self.assertFalse(ok)
        self.assertTrue(any("dangling requires" in e for e in errors))

    def test_accepts_valid_requires(self):
        reg = {"version": 1, "probes": [
            probe("a.one", "ls /sys/block", facts=[
                {"name": "dm_present", "when": "OK", "regex": "dm-",
                 "value_if_match": True, "value_if_nomatch": False}]),
            probe("a.two", "dmsetup ls",
                  requires=[{"fact": "dm_present", "eq": True}]),
        ]}
        ok, errors = check_registry.validate_registry(reg)
        self.assertTrue(ok, errors)

    def test_accepts_real_registry(self):
        registry = check_registry.load_registry(REAL_REGISTRY_PATH)
        ok, errors = check_registry.validate_registry(registry)
        self.assertTrue(ok, errors[:20])


# --------------------------------------------------------------------------
# Evidence classification
# --------------------------------------------------------------------------
class TestClassification(unittest.TestCase):
    def test_ok(self):
        status, _ = tci.classify_status(0, "hello\n")
        self.assertEqual(status, "OK")

    def test_timeout_124(self):
        status, _ = tci.classify_status(124, "")
        self.assertEqual(status, "TIMEOUT")

    def test_timeout_137(self):
        status, _ = tci.classify_status(137, "")
        self.assertEqual(status, "TIMEOUT")

    def test_utility_missing_rc127(self):
        status, _ = tci.classify_status(127, "bash: foo: command not found")
        self.assertEqual(status, "UTILITY_MISSING")

    def test_utility_missing_by_text(self):
        status, _ = tci.classify_status(126, "sh: 1: foo: command not found")
        self.assertEqual(status, "UTILITY_MISSING")

    def test_eacces(self):
        status, _ = tci.classify_status(1, "cat: /etc/shadow: Permission denied")
        self.assertEqual(status, "EACCES")

    def test_enoent(self):
        status, _ = tci.classify_status(1, "cat: /nope: No such file or directory")
        self.assertEqual(status, "ENOENT")

    def test_unsupported(self):
        status, _ = tci.classify_status(1, "ioctl: Operation not supported")
        self.assertEqual(status, "UNSUPPORTED")

    def test_execution_error(self):
        status, _ = tci.classify_status(2, "some other failure")
        self.assertEqual(status, "EXECUTION_ERROR")

    def test_enoent_not_confused_with_utility_missing(self):
        # "not found" alone (no "command not found", rc != 127) -> ENOENT
        status, _ = tci.classify_status(1, "grep: pattern not found")
        self.assertEqual(status, "ENOENT")


# --------------------------------------------------------------------------
# Fact extraction invariants
# --------------------------------------------------------------------------
class TestFactExtraction(unittest.TestCase):
    def test_ok_only_value_from_group(self):
        facts = tci.FactStore()
        p = probe("x", "cmd", facts=[
            {"name": "distro_family", "when": "OK", "regex": r'ID_LIKE=(\w+)',
             "value_from_group": 1}])
        tci.apply_facts(p, ev("x", "OK", 0, "ID_LIKE=debian"), facts)
        self.assertEqual(facts.established.get("distro_family"), "debian")

    def test_non_ok_leaves_unresolved_not_false(self):
        facts = tci.FactStore()
        p = probe("x", "cmd", facts=[
            {"name": "distro_family", "when": "OK", "regex": r'ID_LIKE=(\w+)',
             "value_from_group": 1}])
        tci.apply_facts(p, ev("x", "EACCES", 1, "Permission denied"), facts)
        self.assertNotIn("distro_family", facts.established)
        self.assertIn("distro_family", facts.unresolved)
        self.assertEqual(facts.unresolved["distro_family"][0]["status"], "EACCES")

    def test_timeout_leaves_unresolved(self):
        facts = tci.FactStore()
        p = probe("x", "cmd", facts=[
            {"name": "nvme_present", "when": "OK", "regex": "nvme",
             "value_if_match": True, "value_if_nomatch": False}])
        tci.apply_facts(p, ev("x", "TIMEOUT", 124, ""), facts)
        self.assertNotIn("nvme_present", facts.established)
        self.assertEqual(facts.unresolved["nvme_present"][0]["status"], "TIMEOUT")

    def test_utility_missing_does_not_set_nvme_fact(self):
        facts = tci.FactStore()
        p = probe("x", "nvme list", facts=[
            {"name": "nvme_cli_present", "when": "OK", "nonempty": True}])
        tci.apply_facts(p, ev("x", "UTILITY_MISSING", 127,
                               "bash: nvme: command not found"), facts)
        self.assertNotIn("nvme_cli_present", facts.established)
        self.assertIn("nvme_cli_present", facts.unresolved)

    def test_value_if_nomatch_false_only_on_ok(self):
        # under-claim test: OK + empty listing -> proven absence -> False
        facts = tci.FactStore()
        p = probe("x", "ls /sys/class/nvme", facts=[
            {"name": "nvme_present", "when": "OK", "regex": "nvme",
             "value_if_match": True, "value_if_nomatch": False}])
        tci.apply_facts(p, ev("x", "OK", 0, ""), facts)
        self.assertIs(facts.established.get("nvme_present"), False)

    def test_eacces_over_claim_leaves_unresolved(self):
        # over-claim test: EACCES on the same probe must NOT set false
        facts = tci.FactStore()
        p = probe("x", "ls /sys/class/nvme", facts=[
            {"name": "nvme_present", "when": "OK", "regex": "nvme",
             "value_if_match": True, "value_if_nomatch": False}])
        tci.apply_facts(p, ev("x", "EACCES", 1, "Permission denied"), facts)
        self.assertNotIn("nvme_present", facts.established)
        self.assertIn("nvme_present", facts.unresolved)

    def test_contradiction_marks_contested(self):
        facts = tci.FactStore()
        rule = [{"name": "x", "when": "OK", "regex": r'VAL=(\d+)',
                  "value_from_group": 1}]
        p1 = probe("p1", "cmd1", facts=rule)
        p2 = probe("p2", "cmd2", facts=rule)
        tci.apply_facts(p1, ev("p1", "OK", 0, "VAL=1"), facts)
        tci.apply_facts(p2, ev("p2", "OK", 0, "VAL=2"), facts)
        self.assertNotIn("x", facts.established)
        self.assertIn("x", facts.contested)
        values = {entry["value"] for entry in facts.contested["x"]}
        self.assertEqual(values, {"1", "2"})


# --------------------------------------------------------------------------
# Planner (budget cuts, precondition gating)
# --------------------------------------------------------------------------
class TestPlanner(unittest.TestCase):
    def test_budget_cut_lists_not_attempted_and_no_negative_facts(self):
        probes = [
            probe("a.one", "echo 1", priority=90, facts=[
                {"name": "f1", "when": "OK", "nonempty": True}]),
            probe("a.two", "echo 2", priority=80, facts=[
                {"name": "f2", "when": "OK", "nonempty": True}]),
            probe("a.three", "echo 3", priority=70, facts=[
                {"name": "f3", "when": "OK", "nonempty": True}]),
        ]

        def handler(batch):
            return {p["id"]: ev(p["id"], "OK", 0, "output") for p in batch}

        planner = tci.Planner(probes, tci.FakeExecutor(handler), max_probes=2)
        report = planner.run()
        self.assertEqual(len(planner.ran), 2)
        self.assertEqual(report["not_attempted_budget"], ["a.three"])
        # the cut probe's fact must be absent, not false
        self.assertNotIn("f3", report["established_facts"])
        self.assertNotIn("f3", report.get("contested", {}))

    def test_precondition_gating(self):
        calls = []
        p1 = probe("p1.ready", "echo ready", priority=90, facts=[
            {"name": "ready", "when": "OK", "nonempty": True}])
        p2 = probe("p2.dependent", "echo dep", priority=90,
                   requires=[{"fact": "ready", "eq": True}])

        def handler(batch):
            calls.append(sorted(p["id"] for p in batch))
            return {p["id"]: ev(p["id"], "OK", 0, "x") for p in batch}

        planner = tci.Planner([p1, p2], tci.FakeExecutor(handler), max_rounds=6)
        report = planner.run()
        self.assertEqual(calls[0], ["p1.ready"])
        self.assertIn(["p2.dependent"], calls[1:])
        self.assertEqual(planner.evidence["p2.dependent"]["status"], "OK")
        self.assertEqual(report["not_eligible"], {})

    def test_not_eligible_reports_missing_fact(self):
        p2 = probe("p2.dependent", "echo dep",
                   requires=[{"fact": "never_established", "eq": True}])

        def handler(batch):
            return {p["id"]: ev(p["id"], "OK", 0, "x") for p in batch}

        planner = tci.Planner([p2], tci.FakeExecutor(handler))
        report = planner.run()
        self.assertEqual(len(planner.ran), 0)
        self.assertIn("p2.dependent", report["not_eligible"])
        self.assertIn("never_established", report["not_eligible"]["p2.dependent"])


# --------------------------------------------------------------------------
# Remote script generation / incremental stream parsing
# --------------------------------------------------------------------------
class TestRemoteProtocol(unittest.TestCase):
    def test_escapes_single_quotes(self):
        p = probe("a.one", "echo 'hello world'")
        script = tci.build_remote_script([p])
        self.assertIn("echo '\\''hello world'\\''", script)
        self.assertIn("__TCI_BEGIN %s", script)
        self.assertIn("'a.one'", script)
        self.assertIn("__TCI_END %s", script)

    def test_parse_stream_complete(self):
        # "hello\n" is the command's own output (echo's trailing newline);
        # the second \n is the protocol's own separator before __TCI_RC and
        # must be stripped, not counted as part of stdout.
        script_out = (
            "\n__TCI_BEGIN a.one\nhello\n\n__TCI_RC 0\n__TCI_END a.one\n"
        )
        evidence = tci.parse_stream(script_out, ["a.one"])
        self.assertEqual(evidence["a.one"]["status"], "OK")
        self.assertEqual(evidence["a.one"]["stdout"], "hello\n")

    def test_truncated_stream_session_lost(self):
        # a.one completes fine, a.two begins but the session dies mid-probe,
        # a.three is never even reached.
        script_out = (
            "\n__TCI_BEGIN a.one\nfirst output\n\n__TCI_RC 0\n__TCI_END a.one\n"
            "\n__TCI_BEGIN a.two\npartial output before disconnect"
        )
        evidence = tci.parse_stream(script_out, ["a.one", "a.two", "a.three"])
        self.assertEqual(evidence["a.one"]["status"], "OK")
        self.assertEqual(evidence["a.one"]["stdout"], "first output\n")
        self.assertEqual(evidence["a.two"]["status"], "SESSION_LOST")
        self.assertEqual(evidence["a.three"]["status"], "NOT_ATTEMPTED")


# --------------------------------------------------------------------------
# No secrets in logs
# --------------------------------------------------------------------------
class TestNoSecretsInLog(unittest.TestCase):
    def test_ssh_executor_never_logs_host_user_key(self):
        secret_host = "totally-secret-host.example"
        secret_user = "supersecretuser"
        secret_key = "/fake/path/to/id_totally_secret"
        env_path = os.path.join(THIS_DIR, "_test_fake.env")
        with open(env_path, "w", encoding="utf-8") as f:
            f.write(f"TARGET_HOST={secret_host}\n")
            f.write(f"TARGET_USER={secret_user}\n")
            f.write(f"SSH_KEY_PATH={secret_key}\n")
        try:
            logs = []
            executor = tci.SshExecutor(env_path, log=logs.append)
            fake_completed = mock.Mock(
                stdout=b"\n__TCI_BEGIN a.one\nhi\n\n__TCI_RC 0\n__TCI_END a.one\n",
                stderr=b"")
            with mock.patch("subprocess.run", return_value=fake_completed):
                executor.run_batch([probe("a.one", "echo hi")])
            joined = "\n".join(logs)
            self.assertNotIn(secret_host, joined)
            self.assertNotIn(secret_user, joined)
            self.assertNotIn(secret_key, joined)
            self.assertIn("<HOST>", joined)
            self.assertIn("<USER>", joined)
            self.assertIn("<KEY>", joined)
        finally:
            os.remove(env_path)

    def test_env_file_raw_parser(self):
        env_path = os.path.join(THIS_DIR, "_test_fake2.env")
        with open(env_path, "w", encoding="utf-8") as f:
            f.write("TARGET_HOST=\"quoted-host\"\r\n")
            f.write("# comment\n")
            f.write("TARGET_USER=plainuser\n")
            f.write("SSH_KEY_PATH='C:\\keys\\id_ed25519'\n")
        try:
            env = tci.parse_env_file(env_path)
            self.assertEqual(env["TARGET_HOST"], "quoted-host")
            self.assertEqual(env["TARGET_USER"], "plainuser")
            self.assertEqual(env["SSH_KEY_PATH"], "C:\\keys\\id_ed25519")
        finally:
            os.remove(env_path)


if __name__ == "__main__":
    unittest.main()
