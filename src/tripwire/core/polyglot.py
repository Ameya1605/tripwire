"""Polyglot Registry Architecture: Multi-Ecosystem Supply Chain Adapter."""

from abc import ABC, abstractmethod
from typing import Tuple, List, Dict, Any
from enum import Enum


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    CARGO = "cargo"


class BaseRegistryAdapter(ABC):
    """Abstract adapter interface for detonating packages across distinct package ecosystems."""

    @abstractmethod
    def get_install_command(self, package_name: str, version: str) -> List[str]:
        """Returns the package installation command to execute under trace."""
        pass

    @abstractmethod
    def parse_spec(self, spec: str) -> Tuple[str, str]:
        """Parses package and version string from user input."""
        pass


class NpmAdapter(BaseRegistryAdapter):
    def parse_spec(self, spec: str) -> Tuple[str, str]:
        if "@" in spec.lstrip("@"):
            parts = spec.rsplit("@", 1)
            return parts[0], parts[1]
        return spec, "latest"

    def get_install_command(self, package_name: str, version: str) -> List[str]:
        return ["npm", "install", f"{package_name}@{version}", "--ignore-scripts=false", "--audit=false", "--fund=false"]


class PypiAdapter(BaseRegistryAdapter):
    def parse_spec(self, spec: str) -> Tuple[str, str]:
        if "==" in spec:
            parts = spec.split("==", 1)
            return parts[0], parts[1]
        elif "@" in spec:
            parts = spec.split("@", 1)
            return parts[0], parts[1]
        return spec, "latest"

    def get_install_command(self, package_name: str, version: str) -> List[str]:
        ver_spec = f"{package_name}=={version}" if version != "latest" else package_name
        return ["pip", "install", "--no-cache-dir", ver_spec]


class CargoAdapter(BaseRegistryAdapter):
    def parse_spec(self, spec: str) -> Tuple[str, str]:
        if "@" in spec:
            parts = spec.split("@", 1)
            return parts[0], parts[1]
        return spec, "latest"

    def get_install_command(self, package_name: str, version: str) -> List[str]:
        cmd = ["cargo", "install", package_name]
        if version != "latest":
            cmd.extend(["--version", version])
        return cmd


def get_adapter(ecosystem: Ecosystem) -> BaseRegistryAdapter:
    """Factory creating appropriate ecosystem adapter."""
    if ecosystem == Ecosystem.PYPI:
        return PypiAdapter()
    elif ecosystem == Ecosystem.CARGO:
        return CargoAdapter()
    return NpmAdapter()
