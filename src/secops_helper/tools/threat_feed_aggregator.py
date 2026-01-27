#!/usr/bin/env python3
"""
Threat Feed Aggregator - Centralized Threat Intelligence Management

Aggregate threat feeds from multiple sources, normalize to STIX 2.1,
deduplicate, and export to various platforms.
"""

import sys
import json
import argparse
import sqlite3
import hashlib
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict

try:
    import requests
except ImportError:
    print(
        "Error: requests library not installed. Install with: pip install requests", file=sys.stderr
    )
    sys.exit(1)

try:
    from dotenv import load_dotenv
    import os

    load_dotenv()
except ImportError:
    pass


class ThreatFeedStorage:
    """SQLite storage backend for aggregated threat feeds"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            home = Path.home()
            db_dir = home / ".threatFeedAggregator"
            db_dir.mkdir(exist_ok=True)
            db_path = str(db_dir / "feeds.db")

        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        """Initialize database schema"""
        cursor = self.conn.cursor()

        # IOCs table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_hash TEXT UNIQUE NOT NULL,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                confidence INTEGER DEFAULT 50,
                malware_family TEXT,
                threat_actor TEXT,
                tags TEXT,
                sources TEXT,
                created_at TEXT NOT NULL
            )
        """
        )

        # Sources table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                last_update TEXT,
                ioc_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active'
            )
        """
        )

        # Updates table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name TEXT NOT NULL,
                update_date TEXT NOT NULL,
                iocs_added INTEGER DEFAULT 0,
                iocs_updated INTEGER DEFAULT 0,
                success BOOLEAN DEFAULT 1,
                error_message TEXT
            )
        """
        )

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(ioc_value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_malware_family ON iocs(malware_family)")

        self.conn.commit()

    def store_ioc(self, ioc: Dict) -> bool:
        """Store or update an IOC"""
        try:
            # Calculate hash for deduplication
            ioc_hash = hashlib.sha256(f"{ioc['type']}:{ioc['value']}".encode()).hexdigest()

            cursor = self.conn.cursor()

            # Check if IOC exists
            cursor.execute(
                "SELECT id, sources, confidence FROM iocs WHERE ioc_hash = ?", (ioc_hash,)
            )
            existing = cursor.fetchone()

            now = datetime.utcnow().isoformat() + "Z"

            if existing:
                # Update existing IOC
                existing_sources = json.loads(existing["sources"])
                new_source = {
                    "name": ioc.get("source", "unknown"),
                    "first_seen": ioc.get("first_seen", now),
                }

                # Add source if not already present
                if not any(s["name"] == new_source["name"] for s in existing_sources):
                    existing_sources.append(new_source)

                # Increase confidence based on multiple sources
                new_confidence = min(existing["confidence"] + 10, 100)

                cursor.execute(
                    """
                    UPDATE iocs SET
                        last_seen = ?,
                        confidence = ?,
                        sources = ?,
                        tags = ?
                    WHERE ioc_hash = ?
                """,
                    (
                        now,
                        new_confidence,
                        json.dumps(existing_sources),
                        json.dumps(ioc.get("tags", [])),
                        ioc_hash,
                    ),
                )

                return False  # Updated

            else:
                # Insert new IOC
                cursor.execute(
                    """
                    INSERT INTO iocs (
                        ioc_hash, ioc_type, ioc_value, first_seen, last_seen,
                        confidence, malware_family, threat_actor, tags, sources, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        ioc_hash,
                        ioc["type"],
                        ioc["value"],
                        ioc.get("first_seen", now),
                        now,
                        ioc.get("confidence", 50),
                        ioc.get("malware_family"),
                        ioc.get("threat_actor"),
                        json.dumps(ioc.get("tags", [])),
                        json.dumps(
                            [
                                {
                                    "name": ioc.get("source", "unknown"),
                                    "first_seen": ioc.get("first_seen", now),
                                }
                            ]
                        ),
                        now,
                    ),
                )

                self.conn.commit()
                return True  # Added

        except Exception as e:
            print(f"Error storing IOC: {e}", file=sys.stderr)
            return False

    def search_ioc(
        self,
        value: str = None,
        ioc_type: str = None,
        malware_family: str = None,
        min_confidence: int = 0,
        limit: int = 100,
    ) -> List[Dict]:
        """Search for IOCs"""
        cursor = self.conn.cursor()

        query = "SELECT * FROM iocs WHERE confidence >= ?"
        params = [min_confidence]

        if value:
            query += " AND ioc_value LIKE ?"
            params.append(f"%{value}%")

        if ioc_type:
            query += " AND ioc_type = ?"
            params.append(ioc_type)

        if malware_family:
            query += " AND malware_family LIKE ?"
            params.append(f"%{malware_family}%")

        query += " ORDER BY confidence DESC, last_seen DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()

        results = []
        for row in rows:
            results.append(
                {
                    "id": row["id"],
                    "type": row["ioc_type"],
                    "value": row["ioc_value"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "confidence": row["confidence"],
                    "malware_family": row["malware_family"],
                    "threat_actor": row["threat_actor"],
                    "tags": json.loads(row["tags"]) if row["tags"] else [],
                    "sources": json.loads(row["sources"]) if row["sources"] else [],
                }
            )

        return results

    def get_statistics(self) -> Dict:
        """Get database statistics"""
        cursor = self.conn.cursor()

        # Total IOCs
        cursor.execute("SELECT COUNT(*) as total FROM iocs")
        total = cursor.fetchone()["total"]

        # IOCs by type
        cursor.execute("SELECT ioc_type, COUNT(*) as count FROM iocs GROUP BY ioc_type")
        by_type = {row["ioc_type"]: row["count"] for row in cursor.fetchall()}

        # IOCs by malware family
        cursor.execute(
            """
            SELECT malware_family, COUNT(*) as count
            FROM iocs
            WHERE malware_family IS NOT NULL
            GROUP BY malware_family
            ORDER BY count DESC
            LIMIT 10
        """
        )
        by_malware = {row["malware_family"]: row["count"] for row in cursor.fetchall()}

        # Recent updates
        cursor.execute(
            """
            SELECT source_name, update_date, iocs_added
            FROM updates
            ORDER BY update_date DESC
            LIMIT 5
        """
        )
        recent_updates = [dict(row) for row in cursor.fetchall()]

        return {
            "total_iocs": total,
            "by_type": by_type,
            "top_malware_families": by_malware,
            "recent_updates": recent_updates,
            "database_path": self.db_path,
        }

    def record_update(
        self,
        source_name: str,
        iocs_added: int,
        iocs_updated: int,
        success: bool = True,
        error_message: str = None,
    ):
        """Record a feed update"""
        cursor = self.conn.cursor()

        now = datetime.utcnow().isoformat() + "Z"

        cursor.execute(
            """
            INSERT INTO updates (source_name, update_date, iocs_added, iocs_updated, success, error_message)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (source_name, now, iocs_added, iocs_updated, success, error_message),
        )

        # Update source table
        cursor.execute(
            """
            INSERT OR REPLACE INTO sources (name, last_update, ioc_count, status)
            VALUES (?, ?, (SELECT COUNT(*) FROM iocs), ?)
        """,
            (source_name, now, "active" if success else "error"),
        )

        self.conn.commit()

    def close(self):
        """Close database connection"""
        self.conn.close()


class ThreatFoxFeed:
    """Abuse.ch ThreatFox feed"""

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.base_url = "https://threatfox-api.abuse.ch/api/v1/"

    def fetch_recent(self, days: int = 1) -> List[Dict]:
        """Fetch recent IOCs"""
        try:
            if self.verbose:
                print(f"Fetching ThreatFox IOCs from last {days} days...", file=sys.stderr)

            response = requests.post(
                self.base_url, json={"query": "get_iocs", "days": days}, timeout=30
            )

            if response.status_code == 200:
                data = response.json()

                if data.get("query_status") == "ok":
                    iocs = []
                    for item in data.get("data", []):
                        iocs.append(
                            {
                                "type": self._map_ioc_type(item.get("ioc_type")),
                                "value": item.get("ioc"),
                                "malware_family": item.get("malware_printable"),
                                "threat_actor": item.get("threat_type"),
                                "confidence": item.get("confidence_level", 50),
                                "tags": item.get("tags", []),
                                "first_seen": item.get("first_seen_utc"),
                                "source": "ThreatFox",
                            }
                        )

                    if self.verbose:
                        print(f"Fetched {len(iocs)} IOCs from ThreatFox", file=sys.stderr)

                    return iocs

        except Exception as e:
            print(f"Error fetching ThreatFox: {e}", file=sys.stderr)

        return []

    def _map_ioc_type(self, ioc_type: str) -> str:
        """Map ThreatFox IOC types to standard types"""
        mapping = {
            "ip:port": "ipv4-addr",
            "domain": "domain-name",
            "url": "url",
            "md5_hash": "file-md5",
            "sha256_hash": "file-sha256",
        }
        return mapping.get(ioc_type, ioc_type)


class URLhausFeed:
    """Abuse.ch URLhaus feed"""

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.base_url = "https://urlhaus-api.abuse.ch/v1/"

    def fetch_recent(self, limit: int = 100) -> List[Dict]:
        """Fetch recent URLs"""
        try:
            if self.verbose:
                print(f"Fetching URLhaus recent URLs (limit: {limit})...", file=sys.stderr)

            response = requests.post(
                self.base_url + "urls/recent/", json={"limit": limit}, timeout=30
            )

            if response.status_code == 200:
                data = response.json()

                if data.get("query_status") == "ok":
                    iocs = []
                    for item in data.get("urls", []):
                        iocs.append(
                            {
                                "type": "url",
                                "value": item.get("url"),
                                "malware_family": (
                                    item.get("tags", ["unknown"])[0] if item.get("tags") else None
                                ),
                                "threat_actor": item.get("threat"),
                                "confidence": 70,  # URLhaus is generally high confidence
                                "tags": item.get("tags", []),
                                "first_seen": item.get("dateadded"),
                                "source": "URLhaus",
                            }
                        )

                    if self.verbose:
                        print(f"Fetched {len(iocs)} URLs from URLhaus", file=sys.stderr)

                    return iocs

        except Exception as e:
            print(f"Error fetching URLhaus: {e}", file=sys.stderr)

        return []


class FeedAggregator:
    """Main feed aggregation engine"""

    def __init__(self, storage: ThreatFeedStorage, verbose=False):
        self.storage = storage
        self.verbose = verbose
        self.feeds = {
            "threatfox": ThreatFoxFeed(verbose=verbose),
            "urlhaus": URLhausFeed(verbose=verbose),
        }

    def update_all(self) -> Dict:
        """Update all feeds"""
        results = {}

        for feed_name, feed in self.feeds.items():
            if self.verbose:
                print(f"\n{'='*60}", file=sys.stderr)
                print(f"Updating {feed_name}...", file=sys.stderr)
                print(f"{'='*60}", file=sys.stderr)

            result = self.update_feed(feed_name)
            results[feed_name] = result

        return results

    def update_feed(self, feed_name: str) -> Dict:
        """Update a specific feed"""
        if feed_name not in self.feeds:
            return {"error": f"Unknown feed: {feed_name}"}

        feed = self.feeds[feed_name]
        added = 0
        updated = 0

        try:
            # Fetch IOCs
            if feed_name == "threatfox":
                iocs = feed.fetch_recent(days=1)
            elif feed_name == "urlhaus":
                iocs = feed.fetch_recent(limit=100)
            else:
                iocs = []

            # Store IOCs
            for ioc in iocs:
                is_new = self.storage.store_ioc(ioc)
                if is_new:
                    added += 1
                else:
                    updated += 1

            # Record update
            self.storage.record_update(feed_name, added, updated, success=True)

            if self.verbose:
                print(f"Added: {added}, Updated: {updated}", file=sys.stderr)

            return {"success": True, "added": added, "updated": updated, "total": added + updated}

        except Exception as e:
            error_msg = str(e)
            self.storage.record_update(feed_name, 0, 0, success=False, error_message=error_msg)

            return {"success": False, "error": error_msg}


def format_output_json(data: Dict) -> str:
    """Format output as JSON"""
    return json.dumps(data, indent=2)


def format_output_csv(iocs: List[Dict]) -> str:
    """Format IOCs as CSV"""
    if not iocs:
        return "No IOCs found"

    lines = ["Type,Value,Confidence,Malware Family,First Seen,Last Seen,Sources"]

    for ioc in iocs:
        sources = ",".join([s["name"] for s in ioc.get("sources", [])])
        lines.append(
            f'{ioc["type"]},'
            f'"{ioc["value"]}",'
            f'{ioc["confidence"]},'
            f'"{ioc.get("malware_family", "")}",'
            f'{ioc["first_seen"]},'
            f'{ioc["last_seen"]},'
            f'"{sources}"'
        )

    return "\n".join(lines)


def parse_args():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="Threat Feed Aggregator - Centralized Threat Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update all feeds
  python aggregator.py update

  # Update specific feed
  python aggregator.py update --source threatfox

  # Search for an IOC
  python aggregator.py search "1.2.3.4"

  # Search by type
  python aggregator.py search --type url --min-confidence 70

  # Search by malware family
  python aggregator.py search --malware emotet

  # Get statistics
  python aggregator.py stats

  # Export IOCs to JSON
  python aggregator.py export --format json --output iocs.json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Update command
    update_parser = subparsers.add_parser("update", help="Update threat feeds")
    update_parser.add_argument("--source", help="Specific source to update")
    update_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # Search command
    search_parser = subparsers.add_parser("search", help="Search for IOCs")
    search_parser.add_argument("value", nargs="?", help="IOC value to search")
    search_parser.add_argument("--type", "-t", help="IOC type filter")
    search_parser.add_argument("--malware", "-m", help="Malware family filter")
    search_parser.add_argument("--min-confidence", type=int, default=0, help="Minimum confidence")
    search_parser.add_argument("--limit", "-l", type=int, default=100, help="Result limit")
    search_parser.add_argument("--format", "-f", choices=["json", "csv", "txt"], default="txt")
    search_parser.add_argument("--output", "-o", help="Output file")

    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show statistics")
    stats_parser.add_argument("--format", "-f", choices=["json", "txt"], default="txt")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export IOCs")
    export_parser.add_argument("--format", "-f", choices=["json", "csv"], default="json")
    export_parser.add_argument("--output", "-o", required=True, help="Output file")
    export_parser.add_argument("--min-confidence", type=int, default=50, help="Minimum confidence")

    parser.add_argument("--db", help="Database path")

    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_args()

    if not args.command:
        print("Error: No command specified. Use --help for usage.", file=sys.stderr)
        sys.exit(1)

    # Initialize storage
    storage = ThreatFeedStorage(db_path=args.db)

    # Update command
    if args.command == "update":
        verbose = getattr(args, "verbose", False)
        aggregator = FeedAggregator(storage, verbose=verbose)

        if args.source:
            results = {args.source: aggregator.update_feed(args.source)}
        else:
            results = aggregator.update_all()

        # Print summary
        print("\nUpdate Summary:")
        print("=" * 60)
        for source, result in results.items():
            if result.get("success"):
                print(f"{source}: Added {result['added']}, Updated {result['updated']}")
            else:
                print(f"{source}: FAILED - {result.get('error', 'Unknown error')}")

        storage.close()
        sys.exit(0)

    # Search command
    elif args.command == "search":
        results = storage.search_ioc(
            value=args.value,
            ioc_type=args.type,
            malware_family=args.malware,
            min_confidence=args.min_confidence,
            limit=args.limit,
        )

        # Format output
        if args.format == "json":
            output = format_output_json(
                {
                    "metadata": {
                        "tool": "threat_feed_aggregator",
                        "version": "1.0.0",
                        "query_date": datetime.utcnow().isoformat() + "Z",
                        "results_count": len(results),
                    },
                    "results": results,
                }
            )
        elif args.format == "csv":
            output = format_output_csv(results)
        else:  # txt
            if not results:
                output = "No IOCs found matching criteria"
            else:
                lines = ["=" * 80, f"Found {len(results)} IOCs", "=" * 80, ""]
                for ioc in results[:20]:  # Show first 20
                    lines.append(f"Type: {ioc['type']}")
                    lines.append(f"Value: {ioc['value']}")
                    lines.append(f"Confidence: {ioc['confidence']}/100")
                    if ioc["malware_family"]:
                        lines.append(f"Malware: {ioc['malware_family']}")
                    sources = ", ".join([s["name"] for s in ioc.get("sources", [])])
                    lines.append(f"Sources: {sources}")
                    lines.append(f"Last Seen: {ioc['last_seen']}")
                    lines.append("-" * 80)
                output = "\n".join(lines)

        # Write output
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Results written to {args.output}", file=sys.stderr)
        else:
            print(output)

        storage.close()
        sys.exit(0)

    # Stats command
    elif args.command == "stats":
        stats = storage.get_statistics()

        if args.format == "json":
            output = format_output_json(stats)
        else:  # txt
            lines = [
                "=" * 60,
                "Threat Feed Aggregator Statistics",
                "=" * 60,
                "",
                f"Total IOCs: {stats['total_iocs']}",
                f"Database: {stats['database_path']}",
                "",
                "IOCs by Type:",
            ]

            for ioc_type, count in stats["by_type"].items():
                lines.append(f"  {ioc_type}: {count}")

            lines.append("")
            lines.append("Top Malware Families:")
            for malware, count in stats["top_malware_families"].items():
                lines.append(f"  {malware}: {count}")

            lines.append("")
            lines.append("Recent Updates:")
            for update in stats["recent_updates"]:
                lines.append(
                    f"  {update['source_name']}: {update['iocs_added']} added on {update['update_date'][:10]}"
                )

            lines.append("=" * 60)
            output = "\n".join(lines)

        print(output)
        storage.close()
        sys.exit(0)

    # Export command
    elif args.command == "export":
        results = storage.search_ioc(
            min_confidence=args.min_confidence, limit=10000  # Large limit for export
        )

        if args.format == "json":
            output = format_output_json(
                {
                    "metadata": {
                        "tool": "threat_feed_aggregator",
                        "version": "1.0.0",
                        "export_date": datetime.utcnow().isoformat() + "Z",
                        "total_iocs": len(results),
                    },
                    "iocs": results,
                }
            )
        else:  # csv
            output = format_output_csv(results)

        with open(args.output, "w") as f:
            f.write(output)

        print(f"Exported {len(results)} IOCs to {args.output}", file=sys.stderr)
        storage.close()
        sys.exit(0)

    storage.close()


if __name__ == "__main__":
    main()
