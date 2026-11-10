"""
Verity Store Additions (Priority 3: Shadow-Judge Disagreement Mining & Audit Queue).
"""
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class GrayZoneDisagreementRecord:
    request_id: str
    user_text: str
    classifier_prob: float
    shadow_judge_verdict: str
    triggered_rules: List[str] = field(default_factory=list)
    features: Dict[str, float] = field(default_factory=dict)
    needs_human_review: bool = True


class VerityStore:
    """
    Append-only store for gray-zone shadow-judge disagreement mining.
    Ensures shadow-judge labels are queued for human review before entering the
    568-example training corpus.
    """

    def __init__(self, jsonl_path: Optional[Path] = None):
        self.jsonl_path = jsonl_path
        self._memory_records: List[GrayZoneDisagreementRecord] = []

    def log_gray_zone_event(self, record: GrayZoneDisagreementRecord) -> None:
        self._memory_records.append(record)
        if self.jsonl_path is not None:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            with self.jsonl_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")

    def get_pending_human_review(self) -> List[GrayZoneDisagreementRecord]:
        return [r for r in self._memory_records if r.needs_human_review]
