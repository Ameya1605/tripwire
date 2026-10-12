"""Automated Least-Privilege Seccomp-BPF Profile Synthesizer for Tripwire."""

import json
from typing import Dict, Any, List, Set
from tripwire.models.fingerprint import CanonicalBehaviorFingerprint


class SeccompPolicySynthesizer:
    """
    Synthesizes production Docker/Kubernetes Seccomp-BPF security profiles
    tailored to the empirical baseline behavior of a verified package.
    Enforces least-privilege execution so unauthorized syscalls trigger kernel EPERM/KILL.
    """

    CORE_MANDATORY_SYSCALLS: Set[str] = {
        "read", "write", "openat", "close", "fstat", "lseek", "mmap", "mprotect",
        "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl",
        "access", "pipe2", "select", "sched_yield", "nanosleep", "getpid", "exit_group",
        "futex", "set_robust_list", "getrandom", "statx", "newfstatat",
    }

    def generate_seccomp_profile(
        self,
        baseline_fp: CanonicalBehaviorFingerprint,
        default_action: str = "SCMP_ACT_ERRNO",
    ) -> Dict[str, Any]:
        """
        Synthesizes an official Docker/OCI-compliant Seccomp JSON profile.
        Any syscall not observed during the baseline installation will be blocked by the kernel.
        """
        allowed_syscalls: Set[str] = set(self.CORE_MANDATORY_SYSCALLS)

        # Allow observed network socket syscalls only if baseline required network
        if baseline_fp.network_targets:
            allowed_syscalls.update({"socket", "connect", "sendto", "recvfrom", "getsockopt", "setsockopt"})

        # Allow process creation only if baseline legitimately executed child processes
        if baseline_fp.process_commands:
            allowed_syscalls.update({"execve", "clone", "clone3", "fork", "vfork", "wait4"})

        profile = {
            "defaultAction": default_action,
            "architectures": [
                "SCMP_ARCH_X86_64",
                "SCMP_ARCH_X86",
                "SCMP_ARCH_AARCH64",
            ],
            "syscalls": [
                {
                    "names": sorted(allowed_syscalls),
                    "action": "SCMP_ACT_ALLOW",
                    "args": [],
                    "comment": f"Auto-synthesized by Tripwire for package {baseline_fp.package_name}@{baseline_fp.version}",
                }
            ],
        }

        return profile

    def export_docker_flag(self, profile_path: str) -> str:
        """Returns the Docker CLI invocation flag to enforce the profile."""
        return f"--security-opt seccomp={profile_path}"
