# program.family.audit.beast3.py
# Beast System 3.0 — Deterministic Auditing & Verification Module

from dataclasses import dataclass, field
import time
import hashlib

@dataclass
class AuditRecord:
    module: str
    event_type: str
    payload: dict
    ts: float = field(default_factory=time.time)
    hash: str = ""
    verified: bool = False

    def finalize(self):
        serialized = f"{self.module}{self.event_type}{self.payload}{self.ts}".encode("utf-8")
        self.hash = hashlib.sha256(serialized).hexdigest()

@dataclass
class AuditProfile:
    family_id: str
    records: list = field(default_factory=list)
    last_update: float = field(default_factory=time.time)

    def add_record(self, module: str, event_type: str, payload: dict):
        record = AuditRecord(module, event_type, payload)
        record.finalize()
        self.records.append(record)
        self.last_update = record.ts

    def verify_record(self, index: int, external_hash: str):
        if index < 0 or index >= len(self.records):
            raise IndexError("Audit record index out of range")

        record = self.records[index]
        record.verified = (record.hash == external_hash)
        self.last_update = time.time()
        return record.verified

class AuditEngine:
    def __init__(self, kernel):
        self.kernel = kernel
        self.audit_profiles = {}

    def create_audit_profile(self, family_id: str):
        profile = AuditProfile(family_id)
        self.audit_profiles[family_id] = profile

        return self.kernel.dispatch(
            module="family.audit",
            action="create_audit_profile",
            payload={"family_id": family_id}
        )

    def record_event(self, family_id: str, module: str, event_type: str, payload: dict):
        if family_id not in self.audit_profiles:
            raise ValueError("Audit profile not found")

        profile = self.audit_profiles[family_id]
        profile.add_record(module, event_type, payload)

        return self.kernel.dispatch(
            module="family.audit",
            action="record_event",
            payload={
                "family_id": family_id,
                "module": module,
                "event_type": event_type,
                "payload": payload,
                "ts": profile.last_update
            }
        )

    def verify(self, family_id: str, index: int, external_hash: str):
        if family_id not in self.audit_profiles:
            raise ValueError("Audit profile not found")

        profile = self.audit_profiles[family_id]
        verified = profile.verify_record(index, external_hash)

        return self.kernel.dispatch(
            module="family.audit",
            action="verify",
            payload={
                "family_id": family_id,
                "index": index,
                "external_hash": external_hash,
                "verified": verified
            }
        )

    def get_audit_profile(self, family_id: str):
        return self.audit_profiles.get(family_id, None)
