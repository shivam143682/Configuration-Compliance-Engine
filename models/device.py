"""
models/device.py

Defines the Device class, which wraps a device's name and its raw
configuration text (loaded from a Cisco config file).
"""

from __future__ import annotations

from dataclasses import dataclass


class ConfigLoadError(Exception):
    """Raised when a device configuration file cannot be loaded or is empty."""


@dataclass
class Device:
    name: str
    config_text: str
    config_lines: list

    @classmethod
    def from_file(cls, path: str, device_name: str = None) -> "Device":
        """Load a device configuration from a text file on disk.

        Args:
            path: Path to the Cisco-style configuration file.
            device_name: Optional friendly name; defaults to the filename.
        """
        import os

        if not os.path.isfile(path):
            raise ConfigLoadError(f"Configuration file not found: {path}")

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()

        if not text.strip():
            raise ConfigLoadError(f"Configuration file is empty: {path}")

        name = device_name or os.path.splitext(os.path.basename(path))[0]
        lines = text.splitlines()
        return cls(name=name, config_text=text, config_lines=lines)
