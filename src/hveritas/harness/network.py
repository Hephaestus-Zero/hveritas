"""Worker network allow-list and unconditional oracle host deny-list (§3 Req 10)."""

from __future__ import annotations

from urllib.parse import urlparse


class NetworkPolicyViolationError(PermissionError):
    """Raised when a worker attempts network egress to a non-allowlisted or oracle host."""


class WorkerNetworkPolicy:
    """Enforces deny-by-default allow-list and unconditional held-out oracle host isolation."""

    DEFAULT_ORACLE_DENY_HOSTS = frozenset(
        {
            "oracle.hveritas.internal",
            "heldout.hveritas.internal",
            "verifier.hveritas.internal",
            "169.254.169.254",
        }
    )

    def __init__(
        self,
        allowed_hosts: set[str] | frozenset[str] | None = None,
        oracle_hosts: set[str] | frozenset[str] | None = None,
    ) -> None:
        self.oracle_hosts = (
            frozenset(h.lower() for h in (oracle_hosts or set())) | self.DEFAULT_ORACLE_DENY_HOSTS
        )
        self.allowed_hosts = frozenset(h.lower() for h in (allowed_hosts or set()))

    def check_url(self, url: str) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
        host_port = f"{host}:{port}" if port else host

        if not host:
            raise NetworkPolicyViolationError(f"Malformed URL without hostname: {url!r}")

        if host in self.oracle_hosts or host_port in self.oracle_hosts:
            raise NetworkPolicyViolationError(
                f"I4/Req10 VIOLATION: Held-out oracle host {host_port!r} is strictly unreachable"
            )

        if host not in self.allowed_hosts and host_port not in self.allowed_hosts:
            raise NetworkPolicyViolationError(
                f"Egress host {host_port!r} is not in worker network allow-list"
            )
