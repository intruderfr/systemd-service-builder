#!/usr/bin/env python3
"""
systemd-service-builder
=======================

Generate production-ready systemd service unit files with sensible
security-hardening defaults.

Author : Aslam Ahamed (Head of IT @ Prestige One Developments, Dubai)
License: MIT
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


# -------------------------------------------------------------------------
# Hardening directive presets
# -------------------------------------------------------------------------

# A balanced "tight by default" hardening profile that works for the vast
# majority of long-running daemons. Values picked from the systemd security
# best-practice table (see `systemd-analyze security`) and tightened where
# safe. Override individual entries with --no-harden-<key> if your service
# needs them.
HARDENING_DIRECTIVES: Dict[str, str] = {
    "NoNewPrivileges": "true",
    "PrivateTmp": "true",
    "PrivateDevices": "true",
    "ProtectSystem": "strict",
    "ProtectHome": "true",
    "ProtectKernelTunables": "true",
    "ProtectKernelModules": "true",
    "ProtectKernelLogs": "true",
    "ProtectControlGroups": "true",
    "ProtectClock": "true",
    "ProtectHostname": "true",
    "ProtectProc": "invisible",
    "ProcSubset": "pid",
    "RestrictNamespaces": "true",
    "RestrictRealtime": "true",
    "RestrictSUIDSGID": "true",
    "LockPersonality": "true",
    "MemoryDenyWriteExecute": "true",
    "RemoveIPC": "true",
    "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX",
    "SystemCallArchitectures": "native",
    "SystemCallFilter": "@system-service",
    "CapabilityBoundingSet": "",  # drop ALL capabilities by default
    "AmbientCapabilities": "",
    "UMask": "0077",
}

VALID_RESTART = {"no", "always", "on-failure", "on-abnormal",
                 "on-watchdog", "on-abort", "on-success"}
VALID_TYPES = {"simple", "exec", "forking", "oneshot", "dbus",
               "notify", "notify-reload", "idle"}


# -------------------------------------------------------------------------
# Service spec
# -------------------------------------------------------------------------

@dataclass
class ServiceSpec:
    name: str
    description: str
    exec_start: str
    user: Optional[str] = None
    group: Optional[str] = None
    working_directory: Optional[str] = None
    environment: Dict[str, str] = field(default_factory=dict)
    environment_file: Optional[str] = None
    type: str = "simple"
    restart: str = "on-failure"
    restart_sec: int = 5
    timeout_start_sec: Optional[int] = None
    timeout_stop_sec: Optional[int] = None
    after: List[str] = field(default_factory=lambda: ["network-online.target"])
    wants: List[str] = field(default_factory=lambda: ["network-online.target"])
    wanted_by: List[str] = field(default_factory=lambda: ["multi-user.target"])
    exec_start_pre: List[str] = field(default_factory=list)
    exec_start_post: List[str] = field(default_factory=list)
    exec_stop: Optional[str] = None
    exec_reload: Optional[str] = None
    pid_file: Optional[str] = None
    standard_output: Optional[str] = None  # e.g. "journal", "append:/var/log/x.log"
    standard_error: Optional[str] = None
    syslog_identifier: Optional[str] = None

    # resource limits
    memory_max: Optional[str] = None       # 512M, 2G ...
    memory_high: Optional[str] = None
    cpu_quota: Optional[str] = None        # 50%
    tasks_max: Optional[int] = None
    limit_nofile: Optional[int] = None     # ulimit -n

    # hardening
    harden: bool = True
    read_write_paths: List[str] = field(default_factory=list)
    read_only_paths: List[str] = field(default_factory=list)
    inaccessible_paths: List[str] = field(default_factory=list)
    capability_bounding_set: Optional[str] = None  # override the "" default
    extra_unit: Dict[str, str] = field(default_factory=dict)
    extra_service: Dict[str, str] = field(default_factory=dict)
    extra_install: Dict[str, str] = field(default_factory=dict)


# -------------------------------------------------------------------------
# Validation
# -------------------------------------------------------------------------

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]*$")
SIZE_RE = re.compile(r"^\d+(\.\d+)?(K|M|G|T)?$", re.IGNORECASE)
PCT_RE = re.compile(r"^\d+(\.\d+)?%$")


def _err(msg: str) -> None:
    raise ValueError(msg)


def validate(spec: ServiceSpec) -> List[str]:
    """Validate a spec. Returns a list of warnings (non-fatal)."""
    warnings: List[str] = []

    if not NAME_RE.match(spec.name):
        _err(f"Invalid service name {spec.name!r}: must match {NAME_RE.pattern}")
    if spec.name.endswith(".service"):
        _err("Service name should NOT include the .service suffix")
    if not spec.description.strip():
        _err("Description must not be empty")
    if not spec.exec_start.strip():
        _err("ExecStart must not be empty")
    if spec.type not in VALID_TYPES:
        _err(f"Invalid Type={spec.type!r} (allowed: {sorted(VALID_TYPES)})")
    if spec.restart not in VALID_RESTART:
        _err(f"Invalid Restart={spec.restart!r} (allowed: {sorted(VALID_RESTART)})")

    if spec.memory_max and not SIZE_RE.match(spec.memory_max):
        _err(f"Invalid MemoryMax={spec.memory_max!r} (e.g. 512M, 2G)")
    if spec.memory_high and not SIZE_RE.match(spec.memory_high):
        _err(f"Invalid MemoryHigh={spec.memory_high!r}")
    if spec.cpu_quota and not PCT_RE.match(spec.cpu_quota):
        _err(f"Invalid CPUQuota={spec.cpu_quota!r} (e.g. 50%, 200%)")
    if spec.tasks_max is not None and spec.tasks_max <= 0:
        _err("TasksMax must be positive")
    if spec.limit_nofile is not None and spec.limit_nofile <= 0:
        _err("LimitNOFILE must be positive")

    # ExecStart should normally be an absolute path
    parts = shlex.split(spec.exec_start)
    if parts and not parts[0].startswith("/") and not parts[0].startswith("-"):
        warnings.append(
            f"ExecStart command {parts[0]!r} is not an absolute path; "
            "systemd may fail to locate it. Prefer a full path like /usr/bin/foo.")

    if spec.user == "root":
        warnings.append("User=root: consider running as a dedicated unprivileged user.")
    if not spec.user and spec.harden:
        warnings.append("No User= set; service will run as root. Specify --user for better isolation.")

    # ProtectSystem=strict makes paths read-only — the user must opt in to writable dirs
    if spec.harden and not spec.read_write_paths:
        warnings.append(
            "Hardening on with no ReadWritePaths — service can't write outside /tmp/runtime dirs. "
            "Add --rw-path for any directories the daemon writes to.")

    return warnings


# -------------------------------------------------------------------------
# Rendering
# -------------------------------------------------------------------------

def _quote(value: str) -> str:
    """Quote a value for systemd if it contains spaces or shell metachars."""
    if any(ch in value for ch in ' "\'\\$'):
        return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
    return value


def _render_section(name: str, lines: List[str]) -> str:
    body = "\n".join(lines)
    return f"[{name}]\n{body}\n" if body else ""


def render(spec: ServiceSpec) -> str:
    """Render the spec to a systemd unit-file string."""
    unit_lines: List[str] = [f"Description={spec.description}"]
    for w in spec.wants:
        unit_lines.append(f"Wants={w}")
    for a in spec.after:
        unit_lines.append(f"After={a}")
    for k, v in spec.extra_unit.items():
        unit_lines.append(f"{k}={v}")

    svc_lines: List[str] = [f"Type={spec.type}"]
    if spec.user:
        svc_lines.append(f"User={spec.user}")
    if spec.group:
        svc_lines.append(f"Group={spec.group}")
    if spec.working_directory:
        svc_lines.append(f"WorkingDirectory={spec.working_directory}")
    if spec.environment_file:
        svc_lines.append(f"EnvironmentFile={spec.environment_file}")
    for k, v in spec.environment.items():
        svc_lines.append(f"Environment={k}={_quote(v)}")
    for cmd in spec.exec_start_pre:
        svc_lines.append(f"ExecStartPre={cmd}")
    svc_lines.append(f"ExecStart={spec.exec_start}")
    for cmd in spec.exec_start_post:
        svc_lines.append(f"ExecStartPost={cmd}")
    if spec.exec_stop:
        svc_lines.append(f"ExecStop={spec.exec_stop}")
    if spec.exec_reload:
        svc_lines.append(f"ExecReload={spec.exec_reload}")
    if spec.pid_file:
        svc_lines.append(f"PIDFile={spec.pid_file}")

    svc_lines.append(f"Restart={spec.restart}")
    svc_lines.append(f"RestartSec={spec.restart_sec}")
    if spec.timeout_start_sec is not None:
        svc_lines.append(f"TimeoutStartSec={spec.timeout_start_sec}")
    if spec.timeout_stop_sec is not None:
        svc_lines.append(f"TimeoutStopSec={spec.timeout_stop_sec}")

    if spec.standard_output:
        svc_lines.append(f"StandardOutput={spec.standard_output}")
    if spec.standard_error:
        svc_lines.append(f"StandardError={spec.standard_error}")
    if spec.syslog_identifier:
        svc_lines.append(f"SyslogIdentifier={spec.syslog_identifier}")

    # resource limits
    if spec.memory_max:
        svc_lines.append(f"MemoryMax={spec.memory_max}")
    if spec.memory_high:
        svc_lines.append(f"MemoryHigh={spec.memory_high}")
    if spec.cpu_quota:
        svc_lines.append(f"CPUQuota={spec.cpu_quota}")
    if spec.tasks_max is not None:
        svc_lines.append(f"TasksMax={spec.tasks_max}")
    if spec.limit_nofile is not None:
        svc_lines.append(f"LimitNOFILE={spec.limit_nofile}")

    # hardening
    if spec.harden:
        svc_lines.append("")
        svc_lines.append("# --- hardening (generated by systemd-service-builder) ---")
        directives = dict(HARDENING_DIRECTIVES)
        if spec.capability_bounding_set is not None:
            directives["CapabilityBoundingSet"] = spec.capability_bounding_set
        for k, v in directives.items():
            svc_lines.append(f"{k}={v}")
        if spec.read_write_paths:
            svc_lines.append(f"ReadWritePaths={' '.join(spec.read_write_paths)}")
        if spec.read_only_paths:
            svc_lines.append(f"ReadOnlyPaths={' '.join(spec.read_only_paths)}")
        if spec.inaccessible_paths:
            svc_lines.append(f"InaccessiblePaths={' '.join(spec.inaccessible_paths)}")

    for k, v in spec.extra_service.items():
        svc_lines.append(f"{k}={v}")

    install_lines: List[str] = []
    for w in spec.wanted_by:
        install_lines.append(f"WantedBy={w}")
    for k, v in spec.extra_install.items():
        install_lines.append(f"{k}={v}")

    header = (
        f"# {spec.name}.service — generated by systemd-service-builder\n"
        f"# Install: place at /etc/systemd/system/{spec.name}.service then run\n"
        f"#   sudo systemctl daemon-reload\n"
        f"#   sudo systemctl enable --now {spec.name}.service\n"
    )

    return (
        header
        + _render_section("Unit", unit_lines)
        + "\n"
        + _render_section("Service", svc_lines)
        + "\n"
        + _render_section("Install", install_lines)
    )


# -------------------------------------------------------------------------
# Loading specs from JSON
# -------------------------------------------------------------------------

def from_dict(data: Dict[str, Any]) -> ServiceSpec:
    """Build a ServiceSpec from a dict (e.g. parsed JSON)."""
    allowed = {f for f in ServiceSpec.__dataclass_fields__}
    unknown = set(data) - allowed
    if unknown:
        raise ValueError(f"Unknown config keys: {sorted(unknown)}")
    return ServiceSpec(**data)


def load_config(path: Path) -> ServiceSpec:
    with path.open(encoding="utf-8") as fh:
        return from_dict(json.load(fh))


# -------------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------------

def _parse_env_kv(values: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for v in values or []:
        if "=" not in v:
            raise ValueError(f"Invalid --env entry {v!r}: expected KEY=VALUE")
        k, val = v.split("=", 1)
        if not k:
            raise ValueError(f"Invalid --env entry {v!r}: empty key")
        out[k] = val
    return out


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="systemd-service-builder",
        description=(
            "Generate a hardened systemd .service unit. "
            "Provide flags directly, or pass --config FILE.json."
        ),
    )
    p.add_argument("--config", type=Path,
                   help="Load a ServiceSpec from a JSON file.")
    p.add_argument("--name", help="Service name (without .service suffix).")
    p.add_argument("--description", help="Human-readable description.")
    p.add_argument("--exec", dest="exec_start",
                   help="ExecStart command (absolute path recommended).")
    p.add_argument("--user", help="User to run the service as.")
    p.add_argument("--group", help="Group to run the service as.")
    p.add_argument("--workdir", dest="working_directory",
                   help="WorkingDirectory.")
    p.add_argument("--env", action="append", default=[],
                   help="Environment KEY=VALUE (repeatable).")
    p.add_argument("--env-file", dest="environment_file",
                   help="EnvironmentFile path.")
    p.add_argument("--type", default=None,
                   choices=sorted(VALID_TYPES),
                   help="Service Type= (default: simple).")
    p.add_argument("--restart", default=None,
                   choices=sorted(VALID_RESTART),
                   help="Restart= policy (default: on-failure).")
    p.add_argument("--restart-sec", type=int, default=None,
                   help="RestartSec= (default: 5).")
    p.add_argument("--memory-max",
                   help="MemoryMax (e.g. 512M, 2G).")
    p.add_argument("--cpu-quota",
                   help="CPUQuota (e.g. 50%%).")
    p.add_argument("--tasks-max", type=int, help="TasksMax.")
    p.add_argument("--limit-nofile", type=int, help="LimitNOFILE.")
    p.add_argument("--rw-path", action="append", default=[],
                   help="ReadWritePaths entry (repeatable).")
    p.add_argument("--ro-path", action="append", default=[],
                   help="ReadOnlyPaths entry (repeatable).")
    p.add_argument("--cap", dest="capability_bounding_set",
                   help="CapabilityBoundingSet override (default: empty = drop all).")
    p.add_argument("--no-harden", action="store_true",
                   help="Disable the security hardening block.")
    p.add_argument("--output", "-o", type=Path,
                   help="Write the unit to this path instead of stdout.")
    p.add_argument("--print-spec", action="store_true",
                   help="Also print the resolved spec as JSON to stderr.")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress validation warnings.")
    return p


def build_spec_from_args(args: argparse.Namespace) -> ServiceSpec:
    if args.config:
        spec = load_config(args.config)
    else:
        if not (args.name and args.description and args.exec_start):
            raise SystemExit(
                "error: --name, --description and --exec are required "
                "when --config is not used.")
        spec = ServiceSpec(
            name=args.name,
            description=args.description,
            exec_start=args.exec_start,
        )

    # CLI overrides
    if args.user:
        spec.user = args.user
    if args.group:
        spec.group = args.group
    if args.working_directory:
        spec.working_directory = args.working_directory
    env = _parse_env_kv(args.env)
    if env:
        spec.environment.update(env)
    if args.environment_file:
        spec.environment_file = args.environment_file
    if args.type:
        spec.type = args.type
    if args.restart:
        spec.restart = args.restart
    if args.restart_sec is not None:
        spec.restart_sec = args.restart_sec
    if args.memory_max:
        spec.memory_max = args.memory_max
    if args.cpu_quota:
        spec.cpu_quota = args.cpu_quota
    if args.tasks_max is not None:
        spec.tasks_max = args.tasks_max
    if args.limit_nofile is not None:
        spec.limit_nofile = args.limit_nofile
    if args.rw_path:
        spec.read_write_paths.extend(args.rw_path)
    if args.ro_path:
        spec.read_only_paths.extend(args.ro_path)
    if args.capability_bounding_set is not None:
        spec.capability_bounding_set = args.capability_bounding_set
    if args.no_harden:
        spec.harden = False

    return spec


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        spec = build_spec_from_args(args)
        warnings = validate(spec)
        unit = render(spec)
    except ValueError as exc:
        print(f"systemd-service-builder: error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        args.output.write_text(unit, encoding="utf-8")
        print(f"Wrote {args.output} ({len(unit)} bytes)", file=sys.stderr)
    else:
        sys.stdout.write(unit)

    if not args.quiet:
        for w in warnings:
            print(f"warning: {w}", file=sys.stderr)

    if args.print_spec:
        print(json.dumps(asdict(spec), indent=2, default=str), file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
