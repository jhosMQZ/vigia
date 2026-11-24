"""Exceptions shared by the network layers (kept dependency-free to avoid import cycles)."""
from __future__ import annotations


class StopScan(Exception):
    """Raised when a stop condition (target degradation, cancellation, egress failure) is met."""


class EgressDown(StopScan):
    """The configured egress (proxy/tunnel) cannot be reached. Never answered with a direct connection:
    the scan stops (fail-closed)."""


class UpstreamRefused(ConnectionError):
    """The egress is up but did not open the requested tunnel (target closed/unreachable, or proxy policy).

    ``kind``: refused | unreachable | timeout | forbidden | auth | protocol | failure
    """

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
