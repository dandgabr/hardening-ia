"""Runtime Sandboxing and Process Isolation Engine for AI Agents.

Provides OS-level process containment, Seccomp-BPF syscall filters,
Linux Landlock filesystem rules, Bubblewrap execution builders, and
SSRF/Metadata endpoint network protection. Integrates with ai-jail.
"""

import os
import sys
import shutil
import platform
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from src.core.logger import get_logger
from src.core.os_detector import OSDetector

logger = get_logger("runtime_sandbox")

BLOCKED_SSRF_ENDPOINTS = [
    "169.254.169.254",         # AWS / OpenStack / GCP Instance Metadata
    "metadata.google.internal", # GCP Metadata Hostname
    "100.100.100.200",         # Alibaba Cloud Metadata
    "169.254.170.2",           # AWS ECS Container Task Metadata
    "fd00:ec2::254"            # AWS IPv6 Metadata
]

DANGEROUS_SYSCALLS_DENIED = [
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "kexec_load",
    "kexec_file_load",
    "reboot",
    "swapon",
    "swapoff",
    "sysfs",
    "personality",
    "mount",
    "umount2",
    "pivot_root",
    "chroot"
]


@dataclass
class SandboxProfile:
    tool_name: str
    workspace_dir: Path
    allow_network: bool = True
    read_only_root: bool = True
    blocked_hosts: List[str] = field(default_factory=lambda: list(BLOCKED_SSRF_ENDPOINTS))
    denied_syscalls: List[str] = field(default_factory=lambda: list(DANGEROUS_SYSCALLS_DENIED))
    tmpfs_dirs: List[str] = field(default_factory=lambda: ["/tmp", "/run"])
    read_write_dirs: List[str] = field(default_factory=list)
    read_only_dirs: List[str] = field(default_factory=lambda: ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"])


class RuntimeSandboxManager:
    def __init__(self):
        self.os_type = OSDetector.get_os_type()

    def is_bubblewrap_available(self) -> bool:
        return shutil.which("bwrap") is not None

    def is_ai_jail_available(self) -> bool:
        if shutil.which("ai-jail") is not None:
            return True
        local_bin = Path(__file__).resolve().parent.parent.parent / "scripts" / "extra-tools" / "bin" / "ai-jail"
        return local_bin.exists()

    def generate_seccomp_filter_spec(self, profile: SandboxProfile) -> Dict[str, Any]:
        return {
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": [
                "SCMP_ARCH_X86_64",
                "SCMP_ARCH_X86",
                "SCMP_ARCH_AARCH64"
            ],
            "syscalls": [
                {
                    "names": profile.denied_syscalls,
                    "action": "SCMP_ACT_ERRNO",
                    "errnoRet": 1
                }
            ]
        }

    def generate_landlock_rules(self, profile: SandboxProfile) -> Dict[str, Any]:
        return {
            "version": 1,
            "handled_access_fs": [
                "execute", "write_file", "read_file", "read_dir",
                "remove_dir", "remove_file", "make_char", "make_dir",
                "make_reg", "make_sock", "make_fifo", "make_block", "make_sym"
            ],
            "rules": [
                {
                    "path": str(profile.workspace_dir),
                    "access": ["read_file", "read_dir", "write_file", "remove_file", "make_reg", "make_dir"]
                },
                {
                    "path": "/tmp",
                    "access": ["read_file", "read_dir", "write_file", "remove_file", "make_reg", "make_dir"]
                },
                {
                    "path": "/usr",
                    "access": ["read_file", "read_dir", "execute"]
                },
                {
                    "path": "/etc",
                    "access": ["read_file", "read_dir"]
                }
            ]
        }

    def build_bubblewrap_command(self, command: List[str], profile: SandboxProfile) -> List[str]:
        bwrap_bin = shutil.which("bwrap") or "bwrap"
        cmd = [
            bwrap_bin,
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
            "--new-session"
        ]

        if not profile.allow_network:
            cmd.append("--unshare-net")

        for ro in profile.read_only_dirs:
            if Path(ro).exists():
                cmd.extend(["--ro-bind", ro, ro])

        cmd.extend([
            "--dev", "/dev",
            "--proc", "/proc"
        ])

        for tf in profile.tmpfs_dirs:
            cmd.extend(["--tmpfs", tf])

        ws_str = str(profile.workspace_dir.resolve())
        cmd.extend(["--bind", ws_str, ws_str])
        cmd.extend(["--chdir", ws_str])

        for rw in profile.read_write_dirs:
            if Path(rw).exists():
                cmd.extend(["--bind", rw, rw])

        cmd.extend(command)
        return cmd

    def build_ai_jail_command(self, command: List[str], profile: SandboxProfile) -> List[str]:
        jail_bin = shutil.which("ai-jail")
        if not jail_bin:
            local_bin = Path(__file__).resolve().parent.parent.parent / "scripts" / "extra-tools" / "bin" / "ai-jail"
            if local_bin.exists():
                jail_bin = str(local_bin)
            else:
                jail_bin = "ai-jail"

        cmd = [jail_bin]
        if not profile.allow_network:
            cmd.append("--no-network")
        cmd.extend(["--workspace", str(profile.workspace_dir.resolve())])
        cmd.append("--")
        cmd.extend(command)
        return cmd

    def get_sandbox_diagnostics(self) -> Dict[str, Any]:
        diag = {
            "os": self.os_type,
            "bubblewrap_available": self.is_bubblewrap_available(),
            "ai_jail_available": self.is_ai_jail_available(),
            "seccomp_supported": False,
            "landlock_supported": False
        }

        if self.os_type == "linux":
            status_file = Path("/proc/self/status")
            if status_file.exists():
                try:
                    content = status_file.read_text()
                    diag["seccomp_supported"] = "Seccomp:" in content
                except Exception:
                    pass

            landlock_abi = Path("/sys/kernel/security/landlock")
            diag["landlock_supported"] = landlock_abi.exists()

        return diag
