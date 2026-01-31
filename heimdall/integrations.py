import base64
import json
from typing import Dict, List, Optional

import requests

from .config import DEFAULT_CONFIG


def priority_rank(priority: str) -> int:
    mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return mapping.get(priority or "low", 1)


def map_priority_to_jira(priority: str) -> str:
    mapping = {
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "Highest",
    }
    return mapping.get(priority or "medium", "Medium")


def jira_status_for_incident(status: str) -> str:
    mapping = {
        "open": "New",
        "triaged": "Triaged",
        "investigating": "Investigating",
        "contained": "Contained",
        "resolved": "Resolved",
        "closed": "Resolved",
    }
    return mapping.get(status or "open", "New")


def slack_severity_emoji(priority: str) -> str:
    mapping = {"critical": "🔥", "high": "⚠️", "medium": "ℹ️", "low": "ℹ️"}
    return mapping.get(priority or "medium", "ℹ️")


def safe_join(values: List[object]) -> str:
    return ", ".join(str(value) for value in values if value) or "-"


def build_summary(incident: Dict) -> str:
    category = incident.get("category") or "Activity"
    source_ips = safe_join(incident.get("entities", {}).get("source_ips", []))
    return f"[Heimdall] {category} detected from {source_ips}"


def build_description(incident: Dict, enrich: Dict) -> str:
    return (
        "h2. Incident Overview\n"
        f"*Heimdall Incident ID:* {incident.get('incident_id', '-') }\n"
        "*Detected By:* Heimdall SIEM\n"
        f"*First Seen:* {incident.get('first_seen', '-') }\n"
        f"*Last Seen:* {incident.get('last_seen', '-') }\n"
        f"*Severity:* {incident.get('priority', '-') }\n"
        f"*Category:* {incident.get('category', '-') }\n\n"
        "h2. Correlation Details\n"
        f"*Triggered Rule(s):* {safe_join(incident.get('rule_ids', []))}\n"
        f"*Event Count:* {enrich.get('event_count', 0)}\n"
        f"*Source IP(s):* {safe_join(incident.get('entities', {}).get('source_ips', []))}\n"
        f"*Destination IP(s):* {safe_join(incident.get('entities', {}).get('destination_ips', []))}\n\n"
        "h2. Detection Summary\n"
        f"*Top Signature:* {enrich.get('top_signature', '-') }\n"
        f"*Protocol(s):* {safe_join(enrich.get('protocols', []))}\n\n"
        "h2. MITRE ATT&CK\n"
        f"*Tactic:* {enrich.get('attack_tactic', '-') }\n"
        f"*Technique:* {enrich.get('attack_technique', '-') } ({enrich.get('attack_technique_id', '-') })\n\n"
        "h2. Recommended Actions\n"
        "- Validate source host legitimacy\n"
        "- Assess scope of impact\n"
        "- Monitor for follow-on activity\n\n"
        "h2. Heimdall References\n"
        f"*Internal Incident ID:* {incident.get('incident_id', '-') }"
    )


class JiraSlackIntegration:
    def __init__(self, events_collection, incidents_collection, mongo_lock, incidents_lock) -> None:
        self.events_collection = events_collection
        self.incidents_collection = incidents_collection
        self.mongo_lock = mongo_lock
        self.incidents_lock = incidents_lock

    def enabled(self) -> bool:
        return bool(DEFAULT_CONFIG["jira_base_url"] and DEFAULT_CONFIG["jira_api_token"])

    def slack_enabled(self) -> bool:
        return bool(DEFAULT_CONFIG["slack_webhook_url"])

    def min_priority_met(self, priority: str) -> bool:
        threshold = DEFAULT_CONFIG["integration_min_priority"]
        return priority_rank(priority) >= priority_rank(threshold)

    def enrich_incident(self, incident: Dict) -> Dict:
        event_refs = incident.get("event_refs", [])
        event_count = len(event_refs)
        protocols = set()
        signatures = {}
        attack_tactic = None
        attack_technique = None
        attack_technique_id = None

        if self.events_collection is None or not event_refs:
            return {
                "event_count": event_count,
                "protocols": [],
                "top_signature": "-",
                "attack_tactic": attack_tactic or "-",
                "attack_technique": attack_technique or "-",
                "attack_technique_id": attack_technique_id or "-",
            }

        try:
            with self.mongo_lock:
                cursor = self.events_collection.find(
                    {"event_id": {"$in": event_refs}},
                    {"alert.signature": 1, "network.protocol": 1, "attack": 1},
                )
                for event in cursor:
                    signature = event.get("alert", {}).get("signature")
                    if signature:
                        signatures[signature] = signatures.get(signature, 0) + 1
                    protocol = event.get("network", {}).get("protocol")
                    if protocol:
                        protocols.add(protocol)
                    attack = event.get("attack", {}) or {}
                    if not attack_tactic:
                        attack_tactic = attack.get("tactic")
                    if not attack_technique:
                        attack_technique = attack.get("technique")
                    if not attack_technique_id:
                        attack_technique_id = attack.get("technique_id")
        except Exception:
            pass

        top_signature = "-"
        if signatures:
            top_signature = max(signatures.items(), key=lambda item: item[1])[0]

        return {
            "event_count": event_count,
            "protocols": sorted(protocols),
            "top_signature": top_signature,
            "attack_tactic": attack_tactic or "-",
            "attack_technique": attack_technique or "-",
            "attack_technique_id": attack_technique_id or "-",
        }

    def build_jira_payload(self, incident: Dict, enrich: Dict) -> Dict:
        summary = build_summary(incident)
        description = build_description(incident, enrich)
        fields = {
            "project": {"key": DEFAULT_CONFIG["jira_project_key"]},
            "summary": summary,
            "description": description,
            "issuetype": {"name": DEFAULT_CONFIG["jira_issue_type"]},
            "priority": {"name": map_priority_to_jira(incident.get("priority"))},
            "labels": ["heimdall", incident.get("category") or "incident"],
        }

        if DEFAULT_CONFIG["jira_field_heimdall_id"]:
            fields[DEFAULT_CONFIG["jira_field_heimdall_id"]] = incident.get("incident_id")
        if DEFAULT_CONFIG["jira_field_source_ips"]:
            fields[DEFAULT_CONFIG["jira_field_source_ips"]] = safe_join(
                incident.get("entities", {}).get("source_ips", [])
            )
        if DEFAULT_CONFIG["jira_field_event_count"]:
            fields[DEFAULT_CONFIG["jira_field_event_count"]] = enrich.get("event_count", 0)

        return {"fields": fields}

    def jira_headers(self) -> Dict:
        token = DEFAULT_CONFIG["jira_api_token"]
        email = DEFAULT_CONFIG["jira_email"]
        if email:
            raw = f"{email}:{token}".encode("utf-8")
            auth = base64.b64encode(raw).decode("utf-8")
            auth_header = f"Basic {auth}"
        else:
            auth_header = f"Bearer {token}"
        return {
            "Authorization": auth_header,
            "Content-Type": "application/json",
        }

    def create_jira_issue(self, incident: Dict) -> Optional[Dict]:
        if not self.enabled() or not self.min_priority_met(incident.get("priority")):
            return None
        if incident.get("jira_issue_key"):
            return None

        enrich = self.enrich_incident(incident)
        payload = self.build_jira_payload(incident, enrich)
        url = f"{DEFAULT_CONFIG['jira_base_url'].rstrip('/')}/rest/api/3/issue"

        try:
            response = requests.post(url, headers=self.jira_headers(), json=payload, timeout=8)
            if response.status_code >= 300:
                return None
            data = response.json()
        except Exception:
            return None

        issue_key = data.get("key")
        if not issue_key:
            return None

        issue_url = f"{DEFAULT_CONFIG['jira_base_url'].rstrip('/')}/browse/{issue_key}"
        try:
            with self.incidents_lock:
                self.incidents_collection.update_one(
                    {"incident_id": incident.get("incident_id")},
                    {"$set": {"jira_issue_key": issue_key, "jira_issue_url": issue_url}},
                )
        except Exception:
            pass

        self.send_slack_creation(incident, enrich, issue_url)
        return {"issue_key": issue_key, "issue_url": issue_url}

    def update_jira_issue(self, incident: Dict) -> None:
        if not self.enabled():
            return
        issue_key = incident.get("jira_issue_key")
        if not issue_key:
            return

        enrich = self.enrich_incident(incident)
        payload = self.build_jira_payload(incident, enrich)
        url = f"{DEFAULT_CONFIG['jira_base_url'].rstrip('/')}/rest/api/3/issue/{issue_key}"
        try:
            requests.put(url, headers=self.jira_headers(), json=payload, timeout=8)
        except Exception:
            pass

        self.transition_jira(issue_key, jira_status_for_incident(incident.get("status")))

    def transition_jira(self, issue_key: str, target_status: str) -> None:
        url = f"{DEFAULT_CONFIG['jira_base_url'].rstrip('/')}/rest/api/3/issue/{issue_key}/transitions"
        try:
            response = requests.get(url, headers=self.jira_headers(), timeout=8)
            if response.status_code >= 300:
                return
            data = response.json()
            transitions = data.get("transitions", [])
            transition_id = None
            for transition in transitions:
                if transition.get("name") == target_status:
                    transition_id = transition.get("id")
                    break
            if not transition_id:
                return
            payload = {"transition": {"id": transition_id}}
            requests.post(url, headers=self.jira_headers(), json=payload, timeout=8)
        except Exception:
            return

    def send_slack_creation(self, incident: Dict, enrich: Dict, jira_issue_url: str = "") -> None:
        if not self.slack_enabled() or not self.min_priority_met(incident.get("priority")):
            return
        payload = {
            "text": ":rotating_light: *New Security Incident Detected*",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Category:* {incident.get('category', '-') }\n"
                            f"*Severity:* {incident.get('priority', '-') }\n"
                            f"*Source IP:* {safe_join(incident.get('entities', {}).get('source_ips', []))}"
                        ),
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Heimdall Incident ID:* {incident.get('incident_id', '-') }\n"
                            f"*Event Count:* {enrich.get('event_count', 0)}"
                        ),
                    },
                },
            ],
        }
        if jira_issue_url:
            payload["blocks"].append(
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "View in Jira"},
                            "url": jira_issue_url,
                        }
                    ],
                }
            )
        if DEFAULT_CONFIG["slack_channel"]:
            payload["channel"] = DEFAULT_CONFIG["slack_channel"]

        try:
            requests.post(DEFAULT_CONFIG["slack_webhook_url"], json=payload, timeout=6)
        except Exception:
            return

    def send_slack_update(self, incident: Dict, update_type: str) -> None:
        if not self.slack_enabled():
            return
        emoji = slack_severity_emoji(incident.get("priority"))
        status = incident.get("status", "open")
        jira_url = incident.get("jira_issue_url", "")
        text = f"{emoji} *Incident Update:* {incident.get('incident_id')} is now *{status}*"
        payload = {
            "text": text,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"{emoji} *Incident Update*\n"
                            f"*ID:* {incident.get('incident_id', '-') }\n"
                            f"*Severity:* {incident.get('priority', '-') }\n"
                            f"*Status:* {status}"
                        ),
                    },
                }
            ],
        }
        if jira_url:
            payload["blocks"].append(
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "View in Jira"},
                            "url": jira_url,
                        }
                    ],
                }
            )
        if DEFAULT_CONFIG["slack_channel"]:
            payload["channel"] = DEFAULT_CONFIG["slack_channel"]

        try:
            requests.post(DEFAULT_CONFIG["slack_webhook_url"], json=payload, timeout=6)
        except Exception:
            return

    def on_incident_created(self, incident: Dict) -> None:
        if self.enabled():
            result = self.create_jira_issue(incident)
            if result:
                return
        if self.slack_enabled() and self.min_priority_met(incident.get("priority")):
            enrich = self.enrich_incident(incident)
            self.send_slack_creation(incident, enrich, "")

    def on_incident_updated(self, incident: Dict, reason: str) -> None:
        if self.enabled():
            if not incident.get("jira_issue_key"):
                result = self.create_jira_issue(incident)
                if result:
                    return
            if incident.get("jira_issue_key"):
                self.update_jira_issue(incident)
        if reason in ("priority", "status"):
            self.send_slack_update(incident, reason)
