# Sample captures

Three small public captures from CISA's [ICSNPP](https://github.com/cisagov/ICSNPP) Zeek analyzer test suites, redistributed under their BSD-3-Clause licence (see `LICENSE-ICSNPP.txt` and `NOTICE-ICSNPP.txt`).

| File | What is in it | Size |
|------|---------------|------|
| `icsnpp-modbus.pcap` | A Modbus TCP master polling two controllers, with writes. Shows PLC roles, per-register activity and the "writes to a controller" finding. | 9 KB |
| `icsnpp-s7comm-plus.pcap` | An S7comm-plus session on port 102, captured with `tcpdump -i any` (Linux cooked). Shows a Siemens PLC conversation and a capture type without MAC addresses. | 33 KB |
| `icsnpp-profinet-mixed.pcap` | A PROFINET lab segment: IO-CM over DCE/RPC, LLDP from a switch, ARP, IPv6, DHCP, NetBIOS and LLMNR chatter. Shows device names from evidence, a MAC-only switch, and frames that are counted but not decoded. | 220 KB |

## Opening them

- Start screen: click **open the sample captures**. The three files load as one stitched session.
- Any time: drop one or more of them on the window.
- Command line: `purdungeon examples/icsnpp-modbus.pcap`. On macOS, double-clicking a `.pcap` with purdungeon as the handler does the same.

They are three separate lab networks, not one site, so the stitched view is a tour of what the tool reads rather than a real topology.

## They are also the test fixtures

`crates/core/tests/golden.rs` imports each of these files, asserts its sha256 against `MANIFEST.toml`, and compares what the core made of it with a snapshot in `crates/core/tests/golden/`.
One copy serves both purposes: what a new user sees first is also what CI checks on every change.
