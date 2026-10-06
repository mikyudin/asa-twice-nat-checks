#!/usr/bin/env python3
"""
Verification for "ASA Twice NAT for a Partner VPN: Hide Both Ends in One Rule".

Every claim the post makes about what the lab did is re-read here from the
captured device output, with no network access and no dependencies outside
the standard library.

    python3 asa-twice-nat-checks.py [labs-dir]

The labs directory defaults to ./labs (the companion repo's layout), falling
back to ../labs (this blog's own repo layout).

Groups:

  1. The NAT rule: asa-local's `show nat detail` translates exactly the ranges
     the post describes.
  2. The capture: every packet on asa-partner's inside interface is between a
     pool address and the partner service. No LAN address, no alias.
  3. The translation table: the address in the capture is the one asa-local
     assigned to lan-host, and it sits inside the /28.
  4. The encryption domain: the IKEv2 child SA selectors and both IPsec SAs
     are the post-NAT addresses, with nothing RFC 1918 in them.
  5. The counters: packets in the capture, counted by direction, equal the
     encaps and decaps on both ASAs.
  6. The first packet: lan-host lost seq=0 and only seq=0, and the TCP banner
     came back through the alias.
  7. The September run: its capture is pool-only too, with a different pool
     address, which is what dynamic NAT should do.
"""

import ipaddress
import re
import sys
from pathlib import Path

FAILURES = []

POOL = ipaddress.ip_network("192.0.2.16/28")
SVC = ipaddress.ip_address("198.51.100.10")
ALIAS = ipaddress.ip_address("10.200.0.10")
LAN_HOST = ipaddress.ip_address("192.168.10.10")
# Spelled out: ipaddress.is_private also counts the documentation ranges
# this lab uses (198.51.100.0/24 among them), so it cannot answer this.
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def check(label, got, want):
    ok = got == want
    if not ok:
        FAILURES.append(f"{label}: got {got!r}, want {want!r}")
    print(f"     {'ok  ' if ok else 'FAIL'} {label}: {got}")
    return ok


def find_labs():
    if len(sys.argv) > 1:
        return Path(sys.argv[1])
    here = Path(__file__).resolve().parent
    for cand in (here / "labs", here.parent / "labs"):
        if (cand / "asa-partner-vpn-with-twice-nat.transcript-2026-10-06.txt").exists():
            return cand
    sys.exit("labs directory not found; pass it as the first argument")


def sections(text):
    """Split a transcript on its '## name' headers."""
    out, name = {}, None
    for line in text.splitlines():
        if line.startswith("## "):
            name = line[3:].strip()
            out[name] = []
        elif name:
            out[name].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


def capture_packets(text):
    """(src, dst) for every numbered line of a `show capture` listing."""
    pkts = []
    for m in re.finditer(r"^\s*\d+: [\d:.]+\s+(\d+\.\d+\.\d+\.\d+)(?:\.\d+)? > (\d+\.\d+\.\d+\.\d+)(?:\.\d+)?:?", text, re.M):
        pkts.append((ipaddress.ip_address(m.group(1)), ipaddress.ip_address(m.group(2))))
    return pkts


def counters(text):
    enc = int(re.search(r"#pkts encaps: (\d+)", text).group(1))
    dec = int(re.search(r"#pkts decaps: (\d+)", text).group(1))
    return enc, dec


labs = find_labs()
oct_ = sections((labs / "asa-partner-vpn-with-twice-nat.transcript-2026-10-06.txt").read_text())
sep = sections((labs / "asa-partner-vpn-with-twice-nat.transcript.txt").read_text())
local, partner = oct_["asa-local"], oct_["asa-partner"]
cap = capture_packets(oct_["asa-partner capture"])

print("1. The twice NAT rule")
m = re.search(r"Source - Origin: (\S+), Translated: (\S+)-(\S+)", local)
check("source real", m.group(1), "192.168.10.0/24")
check("source mapped range", (m.group(2), m.group(3)), ("192.0.2.16", "192.0.2.31"))
check("mapped range is the whole /28",
      [ipaddress.ip_address(m.group(2)), ipaddress.ip_address(m.group(3))],
      [POOL.network_address, POOL.broadcast_address])
m = re.search(r"Destination - Origin: (\S+), Translated: (\S+)", local)
check("destination alias -> real", (m.group(1), m.group(2)), ("10.200.0.10/32", "198.51.100.10/32"))

print("2. The capture on asa-partner's inside interface")
check("packets parsed", len(cap), int(re.search(r"(\d+) packets captured", oct_["asa-partner capture"]).group(1)))
ends = {a for p in cap for a in p}
check("every endpoint is the service or a pool address", all(a == SVC or a in POOL for a in ends), True)
check("no RFC 1918 address seen by the partner", any(a in n for a in ends for n in RFC1918), False)
check("alias 10.200.0.10 never seen", ALIAS in ends, False)
pool_addrs = sorted(str(a) for a in ends if a in POOL)
check("pool addresses in use", pool_addrs, ["192.0.2.22"])

print("3. The translation table on asa-local")
m = re.search(r"NAT from inside:(\S+) to outside:(\S+) flags i", local)
check("lan-host translated", m.group(1), str(LAN_HOST))
check("its mapped address is the one in the capture", m.group(2), pool_addrs[0])
check("static twice entry for the service",
      bool(re.search(r"NAT from outside:198\.51\.100\.10 to inside:10\.200\.0\.10\s+flags sT", local)), True)

print("4. The encryption domain")
check("IKEv2 local selector", re.search(r"local selector\s+(\S+ - \S+)", local).group(1),
      "192.0.2.16/0 - 192.0.2.31/65535")
check("IKEv2 remote selector", re.search(r"remote selector (\S+ - \S+)", local).group(1),
      "198.51.100.10/0 - 198.51.100.10/65535")
for name, text, mine, theirs in (("asa-local", local, "192.0.2.16/255.255.255.240", "198.51.100.10/255.255.255.255"),
                                 ("asa-partner", partner, "198.51.100.10/255.255.255.255", "192.0.2.16/255.255.255.240")):
    li = re.search(r"local ident \(addr/mask/prot/port\): \(([\d./]+)/0/0\)", text).group(1)
    ri = re.search(r"remote ident \(addr/mask/prot/port\): \(([\d./]+)/0/0\)", text).group(1)
    check(f"{name} SA idents", (li, ri), (mine, theirs))
    idents = [ipaddress.ip_network(x) for x in (li, ri)]
    check(f"{name} SA has nothing RFC 1918", any(n.overlaps(r) for n in idents for r in RFC1918), False)

print("5. Counters against the capture")
out_ = sum(1 for s, d in cap if s in POOL and d == SVC)
back = sum(1 for s, d in cap if s == SVC and d in POOL)
l_enc, l_dec = counters(local)
p_enc, p_dec = counters(partner)
check("pool -> service packets in capture", out_, 8)
check("service -> pool packets in capture", back, 7)
check("asa-local encaps == outbound captured", l_enc, out_)
check("asa-partner decaps == outbound captured", p_dec, out_)
check("asa-partner encaps == return captured", p_enc, back)
check("asa-local decaps == return captured", l_dec, back)

print("6. lan-host's view")
lh = oct_["lan-host"]
seqs = sorted(int(x) for x in re.findall(r"seq=(\d+)", lh))
check("ping replies", seqs, [1, 2, 3])
check("summary line", re.search(r"(\d+ packets transmitted, \d+ packets received)", lh).group(1),
      "4 packets transmitted, 3 packets received")
check("echo requests reaching the partner == replies lan-host got",
      sum(1 for line in oct_["asa-partner capture"].splitlines() if "echo request" in line), len(seqs))
check("banner through the alias", "partner-svc 198.51.100.10: hello" in lh and "nc -w 5 10.200.0.10 8080" in lh, True)

print("7. The 2026-09-24 run")
sep_cap_text = sep["second run, with a capture on asa-partner's inside interface"]
sep_cap = capture_packets(sep_cap_text)
sep_ends = {a for p in sep_cap for a in p}
check("packets parsed", len(sep_cap), 13)
check("every endpoint is the service or a pool address", all(a == SVC or a in POOL for a in sep_ends), True)
check("pool address that day", sorted(str(a) for a in sep_ends if a in POOL), ["192.0.2.23"])

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILED")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("all checks passed")
