"""Telemetry models representing parsed low-level syscalls and network activity."""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class EventCategory(str, Enum):
    FILE = "file"
    PROCESS = "process"
    NETWORK = "network"
    SECRET = "secret"
    SYSTEM = "system"


class FileOpType(str, Enum):
    OPEN = "open"
    READ = "read"
    WRITE = "write"
    UNLINK = "unlink"
    RENAME = "rename"
    CHMOD = "chmod"
    STAT = "stat"
    OTHER = "other"


class RawTraceRecord(BaseModel):
    """Raw record directly parsed from strace telemetry."""
    line_number: int
    pid: int
    timestamp: str
    syscall: str
    args_raw: str
    ret_val: int
    category: EventCategory = EventCategory.SYSTEM


class FileOpEvent(BaseModel):
    """Normalized file-system interaction event."""
    pid: int
    timestamp: str
    syscall: str
    raw_path: str
    normalized_path: str
    op_type: FileOpType
    flags: List[str] = Field(default_factory=list)
    ret_val: int
    is_sensitive: bool = False
    is_honeytoken: bool = False


class ProcessEvent(BaseModel):
    """Normalized process execution event (execve / clone)."""
    pid: int
    ppid: int
    timestamp: str
    syscall: str
    binary: str
    normalized_binary: str
    argv: List[str] = Field(default_factory=list)
    normalized_argv: List[str] = Field(default_factory=list)
    is_shell: bool = False
    is_network_tool: bool = False  # e.g., curl, wget, nc


class NetworkEvent(BaseModel):
    """Normalized network interaction event (connect / sendto / socket)."""
    pid: int
    timestamp: str
    syscall: str
    family: str  # AF_INET, AF_INET6, AF_UNIX
    ip: Optional[str] = None
    port: Optional[int] = None
    domain: Optional[str] = None
    direction: str = "outbound"
    is_loopback: bool = False
    ret_val: int
