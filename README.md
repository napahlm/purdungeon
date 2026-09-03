# purdungeon

Offline desktop tool for OT/ICS network analysis. Drop a packet capture on the window and see the OT network inside it: every device, its likely role, where it sits in the Purdue model, who it talks to, and which of those conversations deserve a closer look. Think of it as a modern, open-source take on GrassMarlin.

## What it does

1. Drag a `.pcap` / `.pcapng` onto the window (or use the file picker). Parsing runs off the main thread with honest progress stages.
2. The Rust core reads pcap and pcapng (microsecond and nanosecond timestamps, snaplen-truncated, multi-section and cut-off files included) from Ethernet, VLAN-tagged, Linux cooked (`tcpdump -i any`), raw-IP and loopback captures. It decodes IPv4, IPv6 and ARP — an ARP announcement alone is enough to put a device on the map — recognises LLDP and CDP, parses Modbus TCP down to function codes, unit IDs, and coil/register accesses, and names other protocols by port. Every frame it cannot decode is counted by reason and shown in the header rather than silently dropped.
3. Discovery infers a role for every host — PLC, SCADA/master, HMI, engineering workstation, historian, network gear, … — each as a best guess with confidence and evidence, plus a Purdue level. Both are overridable in the UI.
4. The network renders as a **Purdue-layered topology**: assets in horizontal bands by level (process at the bottom, enterprise at the top), node color = level, node shape = role, edge color = protocol, edge width = volume. Conversations that skip a level or cross the control/IT boundary are highlighted.
5. A findings list surfaces what a consultant checks first: cross-zone conduits, who writes to controllers, external addresses on OT segments, scan-like behavior, cleartext control protocols. Each finding highlights the relevant nodes and edges on click.
6. Click any node or edge for detail: identity, classification, per-register read/write activity, function code breakdown, polling cadence.

Everything stays on your machine; nothing leaves the process. OUI vendor lookup uses a bundled table.

## Architecture

The analysis core is a headless Rust crate with no UI dependencies — the desktop app is a thin Tauri shell over it, so the core can be reused from a CLI or tested directly.

```
crates/core/           Headless analysis core (Rust)
  src/ingest/          pcap/pcapng reading, link-type normalisation, frame classification
  src/protocols/       Modbus TCP parser; ARP, LLDP, CDP recognisers; IP protocol names
  src/analysis/        protocol naming, role + Purdue inference, findings
  src/store/           per-session SQLite schema and queries
  tests/               end-to-end imports of synthetic captures, golden-file tests
  tests/fixtures/      three small public captures (CISA ICSNPP, BSD-3) with checksums
  tests/corpus/        manifest of large fetch-only captures (`just fetch-corpus`)

xtask/                 Repository chores (corpus download and verification)

src-tauri/             Desktop shell (Tauri 2)
  src/commands/        IPC commands wrapping the core

src/                   Frontend (Vue 3 + TypeScript + Tailwind)
  canvas/              Konva rendering: nodes, edges, palette
  components/          panels, filters, loading, timeline
  stores/              Pinia state + Purdue band layout
```

## Prerequisites

- [Rust](https://rustup.rs/) (latest stable)
- [Node.js](https://nodejs.org/) 20+ and [pnpm](https://pnpm.io/)

Platform notes: Windows needs WebView2 (pre-installed on 10/11) and VS Build Tools with the C++ workload; Linux needs `libwebkit2gtk-4.1-dev` and friends (see the Tauri docs).

## Getting started

```
pnpm install
pnpm dev
```

## Commands

| Command | What it does |
|---------|-------------|
| `pnpm dev` | Start dev mode (hot reload frontend + Rust backend) |
| `pnpm build` | Build release binary and installers |
| `just test` | Run every Rust test, including the golden-file tests |
| `just lint` | eslint on the frontend, clippy (pedantic, warnings are errors) on the workspace |
| `just deny` | Check the dependency tree against the licence policy in `deny.toml` |
| `just fetch-corpus` | Download the large public captures listed in `crates/core/tests/corpus/manifest.toml` |
| `just golden-update` | Rewrite the golden snapshots after an intended behaviour change |

`just` needs a `sh` on the PATH; on Windows, Git for Windows provides one.

## Tests and fixtures

`cargo test -p purdungeon-core` runs unit tests, end-to-end imports of synthetic captures that exercise every frame type the reader handles, and golden-file tests. A golden test imports a fixed capture, summarises what the core made of it (frame accounting, devices, conversations by protocol, VLANs) and compares that summary with a committed JSON snapshot under `crates/core/tests/golden/`. Three small public captures live in `crates/core/tests/fixtures/` with their checksums; larger ones are fetch-only, listed in `crates/core/tests/corpus/manifest.toml` and checked with `just golden-corpus` once downloaded. When a change intentionally alters what the core reports, `just golden-update` rewrites the snapshots — review the diff, it is the behaviour change.

## License

MIT
