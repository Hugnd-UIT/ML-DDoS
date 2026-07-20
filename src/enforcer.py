from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass
from typing import DefaultDict, List

DEFAULT_MAX_PPS_THRESHOLD: float = 100.0
DEFAULT_BURST_CAPACITY: float = 150.0
DEFAULT_SUSTAINED_WINDOW_SECONDS: float = 60.0
DEFAULT_SUSTAINED_RATIO_THRESHOLD: float = 0.85


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
        sustained_window_seconds: float = DEFAULT_SUSTAINED_WINDOW_SECONDS,
        sustained_ratio_threshold: float = DEFAULT_SUSTAINED_RATIO_THRESHOLD,
    ) -> None:
        self.max_pps_threshold: float = max_pps_threshold
        self.burst_capacity: float = burst_capacity
        self.sustained_window_seconds: float = sustained_window_seconds
        self.sustained_ratio_threshold: float = sustained_ratio_threshold
        self.buckets: DefaultDict[str, List[float]] = defaultdict(
            lambda: [self.burst_capacity, time.monotonic()]
        )
        # Moi phan tu: [window_start_time, cumulative_packets_in_window]
        # Dung de phat hien attacker "nam duoi nguong" lien tuc trong thoi
        # gian dai (low-and-slow), ma Token Bucket tuc thoi khong bat duoc.
        self.sustained: DefaultDict[str, List[float]] = defaultdict(
            lambda: [time.monotonic(), 0.0]
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

    def _check_sustained(self, key: str, packet_count: float) -> bool:
        """Kiem tra xem chu ky nay co dang duy tri toc do gan nguong lien
        tuc trong mot cua so thoi gian dai (mac dinh 60s) hay khong.

        Day la lop phong thu bo sung cho Token Bucket: mot attacker co the
        co tinh giu toc do luon duoi nguong tuc thoi (vd 99 PPS voi
        nguong 100 PPS) de khong bao gio bi DROP, nhung neu duy tri kieu
        do lien tuc trong thoi gian dai thi van la dau hieu bat thuong
        can canh bao (khong chan, chi flag).

        Returns:
            True neu chu ky nay dang o trang thai "nghi ngo duy tri lau dai".
        """
        entry = self.sustained[key]
        now = time.monotonic()
        window_start, cumulative = entry

        elapsed_window = now - window_start
        if elapsed_window >= self.sustained_window_seconds:
            # Het cua so quan sat -> reset lai, bat dau dem lai tu dau
            entry[0] = now
            entry[1] = packet_count
            return False

        entry[1] = cumulative + packet_count

        # Chi phan xet khi da quan sat du lau (>= mot nua cua so) de
        # tranh bao dong gia do 1-2 mau dau tien chua du tin cay.
        if elapsed_window < self.sustained_window_seconds * 0.5:
            return False

        avg_pps = entry[1] / elapsed_window if elapsed_window > 0 else 0.0
        return avg_pps >= (self.max_pps_threshold * self.sustained_ratio_threshold)

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
            is_sustained_suspicious = self._check_sustained(key, packet_count)
            action = (
                "PASS_SUSTAINED_LOW_AND_SLOW"
                if is_sustained_suspicious
                else "PASS_UNDER_THRESHOLD"
            )
            return EnforcementResult(
                action=action,
                signature_key=key,
                tokens_remaining=bucket[0],
            )

        return EnforcementResult(
            action="DROP_RATE_LIMIT_EXCEEDED",
            signature_key=key,
            tokens_remaining=bucket[0],
        )