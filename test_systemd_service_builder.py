"""
Unit tests for systemd_service_builder.

Run with:
    python -m pytest -v
or:
    python -m unittest test_systemd_service_builder.py
"""
import json
import unittest
from pathlib import Path

from systemd_service_builder import (
    HARDENING_DIRECTIVES,
    ServiceSpec,
    build_spec_from_args,
    from_dict,
    main,
    render,
    validate,
    _build_parser,
)


def _basic_spec(**overrides):
    base = dict(
        name="my-app",
        description="My demo daemon",
        exec_start="/usr/bin/my-app --serve",
        user="myapp",
        group="myapp",
        working_directory="/opt/my-app",
    )
    base.update(overrides)
    return ServiceSpec(**base)


class ValidationTests(unittest.TestCase):
    def test_valid_spec_returns_no_errors(self):
        spec = _basic_spec(read_write_paths=["/var/lib/my-app"])
        warnings = validate(spec)
        # No required-path warning since rw paths are set
        self.assertNotIn("ReadWritePaths", " ".join(warnings))

    def test_invalid_name_raises(self):
        with self.assertRaisesRegex(ValueError, "Invalid service name"):
            validate(_basic_spec(name="bad name with spaces"))

    def test_name_must_not_have_service_suffix(self):
        with self.assertRaisesRegex(ValueError, "should NOT include"):
            validate(_basic_spec(name="my-app.service"))

    def test_empty_description_raises(self):
        with self.assertRaisesRegex(ValueError, "Description"):
            validate(_basic_spec(description="   "))

    def test_empty_exec_raises(self):
        with self.assertRaisesRegex(ValueError, "ExecStart"):
            validate(_basic_spec(exec_start=" "))

    def test_invalid_type_raises(self):
        with self.assertRaisesRegex(ValueError, "Invalid Type"):
            validate(_basic_spec(type="bogus"))

    def test_invalid_restart_raises(self):
        with self.assertRaisesRegex(ValueError, "Invalid Restart"):
            validate(_basic_spec(restart="when-i-feel-like-it"))

    def test_memory_max_format_is_validated(self):
        with self.assertRaisesRegex(ValueError, "MemoryMax"):
            validate(_basic_spec(memory_max="lots"))

    def test_cpu_quota_format_is_validated(self):
        with self.assertRaisesRegex(ValueError, "CPUQuota"):
            validate(_basic_spec(cpu_quota="50"))  # missing %

    def test_root_user_emits_warning(self):
        warnings = validate(_basic_spec(user="root", read_write_paths=["/var/lib/x"]))
        self.assertTrue(any("root" in w for w in warnings))

    def test_relative_exec_emits_warning(self):
        warnings = validate(_basic_spec(exec_start="my-app", read_write_paths=["/var/lib/x"]))
        self.assertTrue(any("absolute path" in w for w in warnings))


class RenderTests(unittest.TestCase):
    def test_renders_three_sections(self):
        unit = render(_basic_spec(read_write_paths=["/var/lib/my-app"]))
        self.assertIn("[Unit]", unit)
        self.assertIn("[Service]", unit)
        self.assertIn("[Install]", unit)

    def test_includes_user_and_group(self):
        unit = render(_basic_spec())
        self.assertIn("User=myapp", unit)
        self.assertIn("Group=myapp", unit)

    def test_hardening_directives_emitted_when_enabled(self):
        unit = render(_basic_spec(harden=True))
        for k, v in HARDENING_DIRECTIVES.items():
            self.assertIn(f"{k}={v}", unit, f"missing hardening directive {k}")

    def test_hardening_omitted_when_disabled(self):
        unit = render(_basic_spec(harden=False))
        self.assertNotIn("NoNewPrivileges", unit)
        self.assertNotIn("ProtectSystem", unit)

    def test_environment_quoting(self):
        unit = render(_basic_spec(environment={"GREETING": "hello world"}))
        self.assertIn('Environment=GREETING="hello world"', unit)

    def test_resource_limits_render(self):
        unit = render(_basic_spec(
            memory_max="512M", cpu_quota="50%", tasks_max=100,
            limit_nofile=4096))
        self.assertIn("MemoryMax=512M", unit)
        self.assertIn("CPUQuota=50%", unit)
        self.assertIn("TasksMax=100", unit)
        self.assertIn("LimitNOFILE=4096", unit)

    def test_read_write_paths_join_with_space(self):
        unit = render(_basic_spec(read_write_paths=["/var/lib/x", "/var/log/x"]))
        self.assertIn("ReadWritePaths=/var/lib/x /var/log/x", unit)

    def test_capability_bounding_set_override(self):
        unit = render(_basic_spec(capability_bounding_set="CAP_NET_BIND_SERVICE"))
        self.assertIn("CapabilityBoundingSet=CAP_NET_BIND_SERVICE", unit)

    def test_install_section_includes_wantedby(self):
        unit = render(_basic_spec())
        self.assertIn("WantedBy=multi-user.target", unit)


class ConfigLoadingTests(unittest.TestCase):
    def test_from_dict_round_trip(self):
        data = {
            "name": "demo",
            "description": "Demo",
            "exec_start": "/usr/bin/demo",
            "memory_max": "256M",
        }
        spec = from_dict(data)
        self.assertEqual(spec.memory_max, "256M")

    def test_from_dict_rejects_unknown_keys(self):
        with self.assertRaisesRegex(ValueError, "Unknown config keys"):
            from_dict({"name": "x", "description": "y", "exec_start": "/z",
                       "totally_made_up": True})


class CliTests(unittest.TestCase):
    def test_cli_minimal_invocation_writes_unit(self):
        parser = _build_parser()
        args = parser.parse_args([
            "--name", "demo",
            "--description", "Demo daemon",
            "--exec", "/usr/bin/demo",
            "--user", "demo",
            "--rw-path", "/var/lib/demo",
        ])
        spec = build_spec_from_args(args)
        warnings = validate(spec)
        unit = render(spec)
        self.assertIn("ExecStart=/usr/bin/demo", unit)
        self.assertEqual(warnings, [])

    def test_cli_no_harden_disables_hardening(self):
        parser = _build_parser()
        args = parser.parse_args([
            "--name", "demo",
            "--description", "Demo",
            "--exec", "/usr/bin/demo",
            "--no-harden",
        ])
        spec = build_spec_from_args(args)
        unit = render(spec)
        self.assertNotIn("NoNewPrivileges", unit)

    def test_main_writes_to_output_file(self):
        out = Path("/tmp/svc-builder-test.service")
        if out.exists():
            out.unlink()
        rc = main([
            "--name", "tmpdemo",
            "--description", "tmp",
            "--exec", "/usr/bin/tmpdemo",
            "--user", "tmpdemo",
            "--rw-path", "/var/lib/tmpdemo",
            "-o", str(out),
            "--quiet",
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(out.exists())
        text = out.read_text()
        self.assertIn("ExecStart=/usr/bin/tmpdemo", text)
        out.unlink()


if __name__ == "__main__":
    unittest.main()
