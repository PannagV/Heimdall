from datetime import datetime, timedelta, timezone
from typing import Dict

import numpy as np
import pandas as pd
from pymongo.errors import PyMongoError


def get_metrics(mongo_collection, mongo_lock) -> Dict:
    if mongo_collection is None:
        return {
            "total": 0,
            "last_24h": 0,
            "critical": 0,
            "top_classification": None,
            "by_priority": [],
            "by_classification": [],
            "by_protocol": [],
            "top_signatures": [],
            "hourly_counts": [],
            "avg_per_hour": 0.0,
        }

    now = datetime.now(timezone.utc)
    last_24h_iso = (now - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    base_match = {"event.kind": "alert"}

    def aggregate_list(pipeline):
        try:
            with mongo_lock:
                return list(mongo_collection.aggregate(pipeline))
        except PyMongoError:
            return []

    total_count = aggregate_list([{"$match": base_match}, {"$count": "count"}])
    last_24h_count = aggregate_list(
        [
            {"$match": {**base_match, "ingested_at": {"$gte": last_24h_iso}}},
            {"$count": "count"},
        ]
    )
    critical_count = aggregate_list(
        [{"$match": {**base_match, "event.severity": {"$gte": 4}}}, {"$count": "count"}]
    )

    by_priority = aggregate_list(
        [
            {"$match": base_match},
            {"$group": {"_id": "$event.severity", "count": {"$sum": 1}}},
            {"$sort": {"_id": -1}},
        ]
    )
    by_classification = aggregate_list(
        [
            {"$match": base_match},
            {"$group": {"_id": "$alert.category", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5},
        ]
    )
    by_protocol = aggregate_list(
        [
            {"$match": base_match},
            {"$group": {"_id": "$network.protocol", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5},
        ]
    )
    top_signatures = aggregate_list(
        [
            {"$match": base_match},
            {"$group": {"_id": "$alert.signature", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5},
        ]
    )

    def format_list(items):
        return [
            {"label": item.get("_id") or "Unknown", "count": item.get("count", 0)}
            for item in items
        ]

    top_class = by_classification[0]["_id"] if by_classification else None

    hourly = aggregate_list(
        [
            {"$match": {**base_match, "ingested_at": {"$gte": last_24h_iso}}},
            {
                "$project": {
                    "hour": {
                        "$dateTrunc": {
                            "date": {"$dateFromString": {"dateString": "$ingested_at"}},
                            "unit": "hour",
                        }
                    }
                }
            },
            {"$group": {"_id": "$hour", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}},
        ]
    )

    hourly_series = []
    avg_per_hour = 0.0
    if hourly:
        df = pd.DataFrame(hourly)
        df = df.rename(columns={"_id": "hour"})
        df["hour"] = pd.to_datetime(df["hour"])
        df = df.set_index("hour").asfreq("H", fill_value=0)
        counts = df["count"].to_numpy(dtype=int)
        labels = [ts.strftime("%H:%M") for ts in df.index]
        hourly_series = [
            {"label": label, "count": int(count)}
            for label, count in zip(labels, counts)
        ]
        avg_per_hour = float(np.mean(counts)) if counts.size else 0.0

    return {
        "total": total_count[0]["count"] if total_count else 0,
        "last_24h": last_24h_count[0]["count"] if last_24h_count else 0,
        "critical": critical_count[0]["count"] if critical_count else 0,
        "top_classification": top_class,
        "by_priority": format_list(by_priority),
        "by_classification": format_list(by_classification),
        "by_protocol": format_list(by_protocol),
        "top_signatures": format_list(top_signatures),
        "hourly_counts": hourly_series,
        "avg_per_hour": avg_per_hour,
    }
