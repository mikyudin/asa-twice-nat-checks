# asa-twice-nat-checks

Verification for a partner IPsec VPN on Cisco ASA where one twice NAT rule
hides both ends: LAN hosts leave as addresses from a /28 pool, and they dial a
local alias instead of the partner service's real address. Re-reads every
claim the post makes about the lab from the captured device output.

One file, Python 3 standard library only, no network access, exits non-zero if
any check fails.

```
python3 asa-twice-nat-checks.py
```

Companion to
[ASA Twice NAT for a Partner VPN: Hide Both Ends in One Rule](https://mike.ydn.au/asa-twice-nat-partner-vpn/).

## The lab

Two ASAv 9.23(1) and two Alpine hosts in Cisco Modeling Labs 2.9.0:

```
lan-host ---- asa-local ====IKEv2==== asa-partner ---- partner-svc
192.168.10.10  inside|outside  203.0.113.0/30  outside|inside  198.51.100.10
```

The whole trick is one line on `asa-local`:

```
nat (inside,outside) source dynamic LAN-HOSTS SNAT-POOL destination static PARTNER-SVC-MAPPED PARTNER-SVC-REAL
```

`lan-host` dials `10.200.0.10`. The partner receives traffic from an address in
`192.0.2.16/28` to its real `198.51.100.10`. The crypto ACL is written in those
post-NAT addresses, so the encryption domain contains nothing RFC 1918. The
partner side is a plain policy-based tunnel with no NAT.

## What it checks

**1. The NAT rule.** `show nat detail` translates `192.168.10.0/24` into
`192.0.2.16-192.0.2.31` (the whole /28) and `10.200.0.10` into
`198.51.100.10`.

**2. The capture.** All 15 packets captured on `asa-partner`'s inside interface
are between `192.0.2.22` and `198.51.100.10`. No RFC 1918 address and no alias
ever reaches the partner's network.

**3. The translation table.** The address in the capture is the one `asa-local`
assigned to `lan-host` (`192.168.10.10` to `192.0.2.22`), and the service
appears as a static twice entry (`flags sT`).

**4. The encryption domain.** The IKEv2 child SA selectors and both IPsec SAs
are `192.0.2.16/28` to `198.51.100.10/32`, mirrored on the partner.

**5. The counters reconcile packet for packet.**

| Direction | In partner capture | asa-local | asa-partner |
|---|---|---|---|
| pool to service | 8 | 8 encaps | 8 decaps |
| service to pool | 7 | 7 decaps | 7 encaps |

**6. The first packet.** `lan-host` lost `seq=0` and only `seq=0`: that packet
triggered IKEv2 and was dropped before an SA existed. The three echo requests
that did reach the partner match the three replies `lan-host` received.

**7. The earlier run.** The 2026-09-24 capture is pool-only too, and drew
`192.0.2.23` rather than `.22`, which is what first-come dynamic NAT should do.

## The trap worth knowing

ASA 9.23 rejects a `subnet` object as a dynamic NAT pool with
`Subnet can not be used as mapped source in dynamic NAT policy`. Cisco
documents the restriction. The trouble is that in a day-0 config the ASA logs
that one line, finishes booting, and runs without the NAT rule. Nothing then
matches the crypto ACL and the tunnel is never triggered. Use a `range` object
for the pool and a separate `subnet` object for the ACL, as `labs/` does.

## Labs

`labs/` holds the lab spec, the exported CML lab, the configurations pulled
off the devices, the topology diagram, and both transcripts. See
[`labs/README.md`](labs/README.md).

## Sources

- Cisco, *CLI Book 2: Cisco Secure Firewall ASA Firewall CLI Configuration
  Guide, 9.23*, Network Address Translation chapter
