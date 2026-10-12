"""Syscall and Network Telemetry Parsing Engine for Tripwire."""

import re
from typing import List, Optional, Tuple, Dict, Any
from tripwire.models.telemetry import (
    EventCategory,
    FileOpType,
    RawTraceRecord,
    FileOpEvent,
    ProcessEvent,
    NetworkEvent,
)


class SyscallTracer:
    """
    Parses and categorizes raw strace stream output (-f -tt -s 512).
    Extracts structured file operations, process trees, and network sockets.
    """

    # Regex matching: 12345 09:30:15.123456 syscall(args) = ret
    STRACE_LINE_RE = re.compile(
        r"^(?P<pid>\d+)\s+(?P<ts>\d{2}:\d{2}:\d{2}\.\d+)\s+(?P<syscall>[a-zA-Z0-9_]+)\((?P<args>.*)\)\s+=\s+(?P<ret>-?\d+|0x[0-9a-fA-F]+|\?)"
    )

    # Secondary pattern for resumed lines: 12345 09:30:15.123456 <... openat resumed> ) = 3
    RESUMED_LINE_RE = re.compile(
        r"^(?P<pid>\d+)\s+(?P<ts>\d{2}:\d{2}:\d{2}\.\d+)\s+<\.\.\.\s+(?P<syscall>[a-zA-Z0-9_]+)\s+resumed.*?\)\s+=\s+(?P<ret>-?\d+|0x[0-9a-fA-F]+|\?)"
    )

    # IPv4 connect extractor: {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}
    SOCKADDR_INET_RE = re.compile(
        r"sa_family=(?P<fam>AF_INET6?)[^}]*?sin(?:6)?_port=htons\((?P<port>\d+)\)[^}]*?inet(?:_addr|\d+)?\(\"(?P<ip>[^\"]+)\"\)"
    )

    SHELL_BINARIES = {"sh", "bash", "zsh", "dash", "ash", "powershell", "cmd.exe"}
    NETWORK_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "python", "python3"}

    def __init__(self):
        self.raw_records: List[RawTraceRecord] = []
        self.file_events: List[FileOpEvent] = []
        self.process_events: List[ProcessEvent] = []
        self.network_events: List[NetworkEvent] = []
        self.pid_parent_map: Dict[int, int] = {}

    def parse_trace_file(self, trace_path: str) -> None:
        """Parses an entire strace file line by line."""
        with open(trace_path, "r", encoding="utf-8", errors="replace") as f:
            for idx, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("+++") or line.startswith("---"):
                    continue
                self.parse_line(line, line_number=idx)

    def parse_line(self, line: str, line_number: int = 0) -> Optional[RawTraceRecord]:
        """Parses a single strace line and populates domain models."""
        match = self.STRACE_LINE_RE.match(line)
        if not match:
            # Check resumed line
            match = self.RESUMED_LINE_RE.match(line)
            if not match:
                return None
            args_str = ""
        else:
            args_str = match.group("args")

        pid = int(match.group("pid"))
        timestamp = match.group("ts")
        syscall = match.group("syscall")
        ret_raw = match.group("ret")
        try:
            ret_val = int(ret_raw) if ret_raw != "?" else -1
        except ValueError:
            ret_val = 0

        # Categorize
        category = self._categorize_syscall(syscall)
        record = RawTraceRecord(
            line_number=line_number,
            pid=pid,
            timestamp=timestamp,
            syscall=syscall,
            args_raw=args_str,
            ret_val=ret_val,
            category=category,
        )
        self.raw_records.append(record)

        if category == EventCategory.FILE:
            self._handle_file_event(record)
        elif category == EventCategory.PROCESS:
            self._handle_process_event(record)
        elif category == EventCategory.NETWORK:
            self._handle_network_event(record)

        return record

    def _categorize_syscall(self, syscall: str) -> EventCategory:
        if syscall in {
            "openat", "open", "creat", "unlink", "unlinkat", "rename", "renameat",
            "chmod", "fchmod", "read", "write", "newfstatat", "stat", "lstat"
        }:
            return EventCategory.FILE
        elif syscall in {"execve", "clone", "clone3", "fork", "vfork"}:
            return EventCategory.PROCESS
        elif syscall in {"connect", "sendto", "recvfrom", "socket", "bind", "accept"}:
            return EventCategory.NETWORK
        return EventCategory.SYSTEM

    def _handle_file_event(self, record: RawTraceRecord) -> None:
        """Extracts file paths, operations and flags from file syscalls."""
        path = self._extract_path_from_args(record.syscall, record.args_raw)
        if not path:
            return

        op_type = FileOpType.OTHER
        is_write = False
        if record.syscall in {"openat", "open", "creat"}:
            if any(w in record.args_raw for w in ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"]):
                op_type = FileOpType.WRITE
                is_write = True
            else:
                op_type = FileOpType.OPEN
        elif record.syscall in {"write", "writev"}:
            op_type = FileOpType.WRITE
            is_write = True
        elif record.syscall in {"read", "readv"}:
            op_type = FileOpType.READ
        elif record.syscall in {"unlink", "unlinkat"}:
            op_type = FileOpType.UNLINK
            is_write = True
        elif record.syscall in {"rename", "renameat"}:
            op_type = FileOpType.RENAME
            is_write = True
        elif record.syscall in {"chmod", "fchmod"}:
            op_type = FileOpType.CHMOD

        event = FileOpEvent(
            pid=record.pid,
            timestamp=record.timestamp,
            syscall=record.syscall,
            raw_path=path,
            normalized_path=path,
            op_type=op_type,
            ret_val=record.ret_val,
            is_write=is_write,
        )
        self.file_events.append(event)

    def _handle_process_event(self, record: RawTraceRecord) -> None:
        """Extracts binaries and argument vectors from execve/clone."""
        if record.syscall == "execve":
            binary, argv = self._extract_execve_args(record.args_raw)
            bin_name = binary.split("/")[-1]
            is_shell = bin_name in self.SHELL_BINARIES
            is_net = bin_name in self.NETWORK_TOOLS
            ppid = self.pid_parent_map.get(record.pid, 0)

            event = ProcessEvent(
                pid=record.pid,
                ppid=ppid,
                timestamp=record.timestamp,
                syscall=record.syscall,
                binary=binary,
                normalized_binary=binary,
                argv=argv,
                normalized_argv=argv,
                is_shell=is_shell,
                is_network_tool=is_net,
            )
            self.process_events.append(event)
        elif record.syscall in {"clone", "clone3", "fork", "vfork"}:
            # Child PID is returned on success
            if record.ret_val > 0:
                self.pid_parent_map[record.ret_val] = record.pid

    def _handle_network_event(self, record: RawTraceRecord) -> None:
        """Extracts socket connection targets and IP/port information."""
        if record.syscall in {"connect", "sendto"}:
            match = self.SOCKADDR_INET_RE.search(record.args_raw)
            if match:
                ip = match.group("ip")
                port = int(match.group("port"))
                fam = match.group("fam")
                is_loopback = ip in {"127.0.0.1", "::1", "localhost"}

                event = NetworkEvent(
                    pid=record.pid,
                    timestamp=record.timestamp,
                    syscall=record.syscall,
                    family=fam,
                    ip=ip,
                    port=port,
                    is_loopback=is_loopback,
                    ret_val=record.ret_val,
                )
                self.network_events.append(event)

    @staticmethod
    def _extract_path_from_args(syscall: str, args_str: str) -> Optional[str]:
        """Safely extracts quoted file paths from syscall argument strings."""
        # Examples: AT_FDCWD, "/path/to/file", O_RDONLY... OR "/path/to/file", O_RDONLY
        paths = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', args_str)
        if paths:
            # Usually the first quoted string is the primary path
            return paths[0]
        return None

    @staticmethod
    def _extract_execve_args(args_str: str) -> Tuple[str, List[str]]:
        """Parses execve binary path and string argv array."""
        # Example: "/bin/sh", ["sh", "-c", "echo hello"], 0x7fff...
        # First string is binary
        first_quote = re.search(r'"([^"]+)"', args_str)
        binary = first_quote.group(1) if first_quote else "unknown"

        # Extract argv array inside brackets [...]
        argv: List[str] = []
        bracket_match = re.search(r'\[(.*?)\]', args_str)
        if bracket_match:
            raw_argv = bracket_match.group(1)
            argv = re.findall(r'"([^"]*)"', raw_argv)

        return binary, argv
