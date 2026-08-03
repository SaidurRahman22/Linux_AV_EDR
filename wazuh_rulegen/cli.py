"""Command-line interface: ``scan`` (batch) and ``run`` (real-time daemon)."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .config import Config
from .engine import Engine


def _load_config(path: str | None) -> Config:
    if path:
        return Config.load(path)
    # auto-discover a config.json next to CWD or the project root
    for cand in ("config.json",
                 os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")):
        if os.path.exists(cand):
            return Config.load(cand)
    return Config()


def _apply_overrides(cfg: Config, args: argparse.Namespace) -> None:
    if args.alerts:
        cfg.alerts_file = args.alerts
    if args.output:
        cfg.output_dir = args.output
    if args.id_base is not None:
        cfg.id_base = args.id_base
    if args.ip_feed:
        cfg.ip_feeds = list(cfg.ip_feeds) + args.ip_feed
    if args.hash_feed:
        cfg.hash_feeds = list(cfg.hash_feeds) + args.hash_feed


def _print_summary(stats: dict) -> None:
    print("\n" + "=" * 60)
    print("  wazuh_rulegen summary")
    print("=" * 60)
    print(f"  alerts processed : {stats.get('alerts_processed', 0)}")
    print(f"  indicators (IOCs): {stats.get('indicators', 0)}")
    for t, n in sorted(stats.get("by_type", {}).items()):
        print(f"      - {t:<20}: {n}")
    print(f"  elapsed          : {stats.get('elapsed_seconds', 0)}s")
    print("=" * 60 + "\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wazuh-rulegen",
        description="Generate Wazuh detection rules from suspicious activity in the "
                    "manager's alert log (brute force, malicious IPs, malicious artifacts).")
    p.add_argument("--version", action="version", version=f"wazuh-rulegen {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("-c", "--config", help="path to config.json")
        sp.add_argument("--alerts", help="override path to alerts.json")
        sp.add_argument("--output", help="override output directory")
        sp.add_argument("--id-base", type=int, help="override base rule id (>=100000)")
        sp.add_argument("--ip-feed", action="append", help="extra malicious-IP feed file (repeatable)")
        sp.add_argument("--hash-feed", action="append", help="extra malicious-hash feed file (repeatable)")
        sp.add_argument("-v", "--verbose", action="store_true")

    sp_scan = sub.add_parser("scan", help="one-shot batch scan of existing alerts")
    common(sp_scan)
    sp_scan.add_argument("--include-archives", action="store_true",
                         help="also scan rotated alerts under alerts/<year>/<month>/")
    sp_scan.add_argument("--print-only", action="store_true",
                         help="print generated rules to stdout instead of writing files")

    sp_run = sub.add_parser("run", help="daemon: tail alerts and generate rules in real time")
    common(sp_run)
    sp_run.add_argument("--once", action="store_true",
                        help="process currently-available new lines then exit (for testing)")

    sp_upd = sub.add_parser("update-feeds",
                            help="fetch public threat-intel feeds and merge into feed files")
    common(sp_upd)
    sp_upd.add_argument("--timeout", type=float, default=30.0, help="per-source HTTP timeout (s)")
    sp_upd.add_argument("--max-per-source", type=int, default=400)
    sp_upd.add_argument("--dry-run", action="store_true", help="show what would change, write nothing")

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    cfg = _load_config(args.config)
    _apply_overrides(cfg, args)

    if cfg.id_base < 100000:
        print("ERROR: Wazuh custom rule ids must be >= 100000 (got "
              f"{cfg.id_base}).", file=sys.stderr)
        return 2

    engine = Engine(cfg, verbose=args.verbose)
    try:
        if args.command == "scan":
            stats = engine.scan(include_archives=args.include_archives,
                                print_only=args.print_only)
            if not args.print_only:
                _print_summary(stats)
        elif args.command == "run":
            engine.run(once=args.once)
        elif args.command == "update-feeds":
            from .feedupdate import update_feeds
            print("Updating threat-intel feeds...")
            res = update_feeds(cfg, timeout=args.timeout,
                               max_per_source=args.max_per_source, dry_run=args.dry_run)
            print(f"fetched: {res['ips_fetched']} ips, {res['hashes_fetched']} hashes | "
                  f"written: {res['ip_written']} ips, {res['hash_written']} hashes"
                  + (f" | {len(res['errors'])} source error(s)" if res['errors'] else ""))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
