from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass
from typing import DefaultDict, List

DEFAULT_MAX_PPS_THRESHOLD: float = 100.0
DEFAULT_BURST_CAPACITY: float = 150.0


@dataclass
class EnforcementResult:
    action: str
    signature_key: str | None
    tokens_remaining: float | None


class TokenBucketEnforcer:
    def __init__(
        self,
        max_pps_threshold: float = DEFAULT_MAX_PPS_THRESHOLD,
        burst_capacity: float = DEFAULT_BURST_CAPACITY,
    ) -> None:
        self.max_pps_threshold: float = max_pps_threshold
        self.burst_capacity: float = burst_capacity
        self.buckets: DefaultDict[str, List[float]] = defaultdict(
            lambda: [self.burst_capacity, time.monotonic()]
        )

    @staticmethod
    def build_signature_key(
        protocol: str, dst_port: int, fwd_len_mean: float
    ) -> str:
        rounded_len = round(fwd_len_mean, -1)
        return f"PROTO:{protocol}_PORT:{dst_port}_LEN:{rounded_len}"

    def _refill(self, key: str) -> None:
        bucket = self.buckets[key]
        current_tokens, last_time = bucket

        now = time.monotonic()
        elapsed = now - last_time

        refill_amount = elapsed * self.max_pps_threshold
        new_tokens = min(self.burst_capacity, current_tokens + refill_amount)

        bucket[0] = new_tokens
        bucket[1] = now

    def evaluate_traffic(
        self,
        ai_label: int,
        protocol: str,
        dst_port: int,
        fwd_len_mean: float,
        packet_count: float = 1.0,
    ) -> EnforcementResult:
        if ai_label == 0:
            return EnforcementResult(
                action="PASS_BENIGN",
                signature_key=None,
                tokens_remaining=None,
            )

        key = self.build_signature_key(protocol, dst_port, fwd_len_mean)
        self._refill(key)
        bucket = self.buckets[key]

        if bucket[0] >= packet_count:
            bucket[0] -= packet_count
            return EnforcementResult(
                action="PASS_UNDER_THRESHOLD",
                signature_key=key,
                tokens_remaining=bucket[0],
            )

        return EnforcementResult(
            action="DROP_RATE_LIMIT_EXCEEDED",
            signature_key=key,
            tokens_remaining=bucket[0],
        )