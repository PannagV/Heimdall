import json
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from pymongo import ReturnDocument
from pymongo.errors import PyMongoError

from .config import DEFAULT_CONFIG
from .hces import normalize_iso_timestamp

INCIDENTS_MONGO_VALIDATOR = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": [
            "incident_id",
            "status",
            "priority",
            "category",
            "entities",
            "event_refs",
            "first_seen",
            "last_seen",
            "rule_ids",
        ],
        "properties": {
            "incident_id": {"bsonType": "string"},
            "status": {"bsonType": "string"},
            "priority": {"bsonType": "string"},
            "category": {"bsonType": "string"},
            "entities": {"bsonType": "object"},
            "event_refs": {"bsonType": "array"},
            "first_seen": {"bsonType": "string"},
            "last_seen": {"bsonType": "string"},
            "rule_ids": {"bsonType": "array"},
        },
        "additionalProperties": True,
    }
}


class CorrelationEngine:
    def __init__(
        self,
        mongo_client,
        events_collection,
        incidents_collection,
        mongo_lock,
        incidents_lock,
        rules_path: Optional[str] = None,
    ) -> None:
        self.mongo_client = mongo_client
        self.events_collection = events_collection
        self.incidents_collection = incidents_collection
        self.mongo_lock = mongo_lock
        self.incidents_lock = incidents_lock
        self.rules_path = rules_path or DEFAULT_CONFIG["correlation_rules_path"]
        self.rules = self.load_rules()
        self.last_cleanup: Optional[datetime] = None

    def load_rules(self) -> List[Dict]:
        try:
            with open(self.rules_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
                if isinstance(data, list):
                    return data
                if isinstance(data, dict) and isinstance(data.get("rules"), list):
                    return data["rules"]
        except Exception:
            return []
        return []

    @staticmethod
    def get_field(data: Dict, path: str) -> Optional[object]:
        current: object = data
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    @staticmethod
    def match_value(field_value: object, expected: object) -> bool:
        if field_value is None:
            return False
        if isinstance(expected, list):
            if isinstance(field_value, list):
                return any(item in field_value for item in expected)
            return field_value in expected
        if isinstance(field_value, list):
            return expected in field_value
        return field_value == expected

    def rule_matches_event(self, event: Dict, rule: Dict) -> bool:
        match_block = rule.get("match", {})
        if not isinstance(match_block, dict):
            return False
        for field_path, expected in match_block.items():
            if not self.match_value(self.get_field(event, field_path), expected):
                return False
        return True

    @staticmethod
    def parse_iso_datetime(timestamp: Optional[str]) -> Optional[datetime]:
        normalized = normalize_iso_timestamp(timestamp)
        if not normalized:
            return None
        ts = normalized.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(ts)
        except Exception:
            return None

    def event_entities(self, event: Dict) -> Dict[str, List[object]]:
        entities = {
            "source_ips": [],
            "destination_ips": [],
            "users": [],
            "alert_ids": [],
            "attack_techniques": [],
        }
        source_ip = self.get_field(event, "source.ip")
        dest_ip = self.get_field(event, "destination.ip")
        user_name = self.get_field(event, "user.name")
        alert_id = self.get_field(event, "alert.id")
        technique_id = self.get_field(event, "attack.technique_id")

        if source_ip:
            entities["source_ips"].append(source_ip)
        if dest_ip:
            entities["destination_ips"].append(dest_ip)
        if user_name:
            entities["users"].append(user_name)
        if alert_id is not None:
            entities["alert_ids"].append(alert_id)
        if technique_id:
            entities["attack_techniques"].append(technique_id)
        return entities

    def group_by_values(self, event: Dict, fields: List[str]) -> Optional[Dict[str, object]]:
        values: Dict[str, object] = {}
        for field_path in fields:
            value = self.get_field(event, field_path)
            if value is None:
                return None
            values[field_path] = value
        return values

    @staticmethod
    def incident_entity_field(field_path: str) -> Optional[str]:
        mapping = {
            "source.ip": "entities.source_ips",
            "destination.ip": "entities.destination_ips",
            "user.name": "entities.users",
            "alert.id": "entities.alert_ids",
            "attack.technique_id": "entities.attack_techniques",
        }
        return mapping.get(field_path)

    @staticmethod
    def priority_rank(priority: str) -> int:
        mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return mapping.get(priority, 1)

    def pick_priority(self, existing: str, incoming: str) -> str:
        return incoming if self.priority_rank(incoming) > self.priority_rank(existing) else existing

    def build_rule_query(
        self, rule: Dict, group_values: Dict[str, object], window_start: str, window_end: str
    ) -> Dict:
        query: Dict[str, object] = {
            "timestamp": {"$gte": window_start, "$lte": window_end},
        }
        match_block = rule.get("match", {})
        if isinstance(match_block, dict):
            for field_path, expected in match_block.items():
                if isinstance(expected, list):
                    query[field_path] = {"$in": expected}
                else:
                    query[field_path] = expected
        for field_path, value in group_values.items():
            query[field_path] = value
        return query

    def find_candidate_incident(self, group_values: Dict[str, object], window_start: str) -> Optional[Dict]:
        if self.incidents_collection is None:
            return None
        query: Dict[str, object] = {
            "status": {"$ne": "closed"},
            "last_seen": {"$gte": window_start},
        }
        for field_path, value in group_values.items():
            entity_field = self.incident_entity_field(field_path)
            if entity_field:
                query[entity_field] = value
        try:
            with self.incidents_lock:
                return self.incidents_collection.find_one(query, sort=[("last_seen", -1)])
        except PyMongoError:
            return None

    def next_incident_id(self, reference_time: datetime) -> str:
        if self.mongo_client is None:
            return f"INC-{reference_time.year}-00000"
        db = self.mongo_client["alerts"]
        counters = db["counters"]
        year_key = str(reference_time.year)
        try:
            result = counters.find_one_and_update(
                {"_id": f"incident-{year_key}"},
                {"$inc": {"seq": 1}},
                upsert=True,
                return_document=ReturnDocument.AFTER,
            )
            seq = result.get("seq", 1)
            return f"INC-{year_key}-{seq:05d}"
        except PyMongoError:
            return f"INC-{reference_time.year}-00000"

    def close_stale_incidents(self, current_time: datetime) -> None:
        if self.incidents_collection is None:
            return
        if self.last_cleanup and (current_time - self.last_cleanup) < timedelta(seconds=60):
            return
        cutoff = current_time - timedelta(minutes=DEFAULT_CONFIG["incident_timeout_minutes"])
        cutoff_iso = cutoff.isoformat().replace("+00:00", "Z")
        try:
            with self.incidents_lock:
                self.incidents_collection.update_many(
                    {"status": {"$ne": "closed"}, "last_seen": {"$lt": cutoff_iso}},
                    {"$set": {"status": "closed"}},
                )
        except PyMongoError:
            pass
        self.last_cleanup = current_time

    def correlate_event(self, event: Dict) -> Dict:
        if self.incidents_collection is None or self.events_collection is None:
            return event
        if event.get("event", {}).get("kind") != "alert":
            return event

        event_time = self.parse_iso_datetime(event.get("timestamp")) or datetime.now(timezone.utc)
        self.close_stale_incidents(event_time)
        event_iso = event_time.isoformat().replace("+00:00", "Z")

        for rule in self.rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("enabled") is False:
                continue
            if not self.rule_matches_event(event, rule):
                continue

            group_fields = rule.get("group_by", []) or []
            group_values = self.group_by_values(event, group_fields) if group_fields else {}
            if group_fields and not group_values:
                continue

            threshold = rule.get("threshold", {}) or {}
            threshold_count = int(threshold.get("count", 1))
            window_minutes = int(threshold.get("window_minutes", 5))
            window_start = (event_time - timedelta(minutes=window_minutes)).isoformat().replace(
                "+00:00", "Z"
            )

            query = self.build_rule_query(rule, group_values, window_start, event_iso)
            try:
                with self.mongo_lock:
                    existing_count = self.events_collection.count_documents(query)
            except PyMongoError:
                existing_count = 0
            total_count = existing_count + 1

            if total_count < threshold_count:
                continue

            candidate = self.find_candidate_incident(group_values, window_start) if group_fields else None
            rule_incident = rule.get("incident", {}) or {}
            incident_priority = rule_incident.get("priority", "low")
            incident_category = rule_incident.get("category", "unknown")
            rule_id = rule.get("rule_id") or "UNKNOWN"
            entities = self.event_entities(event)

            if candidate:
                incident_id = candidate.get("incident_id")
                new_priority = self.pick_priority(candidate.get("priority", "low"), incident_priority)
                update_doc = {
                    "$set": {"last_seen": event_iso, "priority": new_priority},
                    "$addToSet": {
                        "event_refs": event.get("event_id"),
                        "rule_ids": rule_id,
                        "entities.source_ips": {"$each": entities.get("source_ips", [])},
                        "entities.destination_ips": {"$each": entities.get("destination_ips", [])},
                        "entities.users": {"$each": entities.get("users", [])},
                        "entities.alert_ids": {"$each": entities.get("alert_ids", [])},
                        "entities.attack_techniques": {"$each": entities.get("attack_techniques", [])},
                    },
                }
                try:
                    with self.incidents_lock:
                        self.incidents_collection.update_one(
                            {"incident_id": incident_id}, update_doc
                        )
                except PyMongoError:
                    pass

                event["incident"] = {
                    "id": incident_id,
                    "status": candidate.get("status", "open"),
                    "priority": new_priority,
                    "first_seen": candidate.get("first_seen"),
                    "last_seen": event_iso,
                }
                return event

            incident_id = self.next_incident_id(event_time)
            incident_doc = {
                "incident_id": incident_id,
                "status": "open",
                "priority": incident_priority,
                "category": incident_category,
                "entities": {
                    "source_ips": entities.get("source_ips", []),
                    "destination_ips": entities.get("destination_ips", []),
                    "users": entities.get("users", []),
                    "alert_ids": entities.get("alert_ids", []),
                    "attack_techniques": entities.get("attack_techniques", []),
                },
                "event_refs": [event.get("event_id")],
                "first_seen": event_iso,
                "last_seen": event_iso,
                "rule_ids": [rule_id],
            }
            try:
                with self.incidents_lock:
                    self.incidents_collection.insert_one(incident_doc)
            except PyMongoError:
                pass

            event["incident"] = {
                "id": incident_id,
                "status": "open",
                "priority": incident_priority,
                "first_seen": event_iso,
                "last_seen": event_iso,
            }
            return event

        return event


class IncidentCloser(threading.Thread):
    def __init__(self, engine: CorrelationEngine, interval_seconds: int = 60) -> None:
        super().__init__(daemon=True)
        self.engine = engine
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            self.engine.close_stale_incidents(datetime.now(timezone.utc))
            time.sleep(self.interval_seconds)
