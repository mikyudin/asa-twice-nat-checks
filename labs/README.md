# Labs

Everything here came off one Cisco Modeling Labs 2.9.0 lab: two ASAv 9.23(1)
(`asav-9-23-1`) and two Alpine hosts.

| File | What it is |
|---|---|
| `test-asa-partner-vpn-nat.yaml` | The lab spec, in the compact format the author's tooling builds from. The source of truth, and the only file that carries the pre-shared key. |
| `asa-partner-vpn-with-twice-nat.yaml` | The same lab exported from CML 2.9.0 (schema `0.3.0`). Import it directly into CML. |
| `asa-partner-vpn-with-twice-nat.configs/` | Running configs pulled off the devices. |
| `asa-partner-vpn-with-twice-nat.svg` | Topology diagram. |
| `asa-partner-vpn-with-twice-nat.transcript.txt` | Verification run, 2026-09-24. |
| `asa-partner-vpn-with-twice-nat.transcript-2026-10-06.txt` | Re-run from a clean state, 2026-10-06. This is the one the post and the checks script use. |

Three things to know before reusing these:

- **The pulled `.cfg` files cannot rebuild the tunnel.** `show run` masks the
  pre-shared key as `*****`. Build from either `.yaml` instead.
- **The key `LabOnly-Change-Me-1` is a placeholder**, and the Alpine hosts use
  CML's default `cisco` / `cisco`. Neither belongs anywhere real.
- **Every address is from a documentation range or RFC 1918.** `192.0.2.0/24`,
  `198.51.100.0/24` and `203.0.113.0/24` are reserved by RFC 5737 and must not
  be used as a real partner pool.
