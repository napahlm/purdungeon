# coil-sniffer

Offline desktop tool for OT/ICS network analysis. Drop a pcap file, get a network topology canvas and communication timeline. Think of it as a modern, open-source take on GrassMarlin.

## What it does

1. Load a .pcap or .pcapng capture file (drag-drop or file picker)
2. Rust backend parses the capture and extracts L2/L3/L4 info, identifies OT protocols (Modbus TCP for now)
3. Parsed data is stored in an embedded SQLite database (one db per pcap)
4. Frontend renders two views:
   - **Network topology canvas** -- interactive, draggable nodes, pan/zoom, force-directed layout
   - **Timeline** -- scrub through time, filter the topology view by time window

## Prerequisites

### All platforms

- [Rust](https://rustup.rs/) (latest stable)
- [Node.js](https://nodejs.org/) 20+ and [pnpm](https://pnpm.io/)

### Windows

- WebView2 (pre-installed on Windows 10/11)
- Visual Studio Build Tools with C++ workload (for rusqlite bundled SQLite compilation)

### Linux (Ubuntu/Debian)

```
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
  libssl-dev libayatana-appindicator3-dev librsvg2-dev
```

## Getting started

```
pnpm install
pnpm dev
```

## Build

```
pnpm build
```

Produces platform-specific installers in `src-tauri/target/release/bundle/`.

## Project structure

```
src/                   Frontend (Vue 3 + TypeScript + Tailwind)
  components/
    canvas/            Topology canvas (Konva.js)
    timeline/          Timeline slider
    common/            Shared UI components
  stores/              Pinia state management
  composables/         Shared logic
  types/               TypeScript interfaces

src-tauri/             Backend (Rust)
  src/
    commands/          Tauri IPC command handlers
    parser/            Pcap file parsing
    protocols/         OT protocol dissectors
    db/                SQLite schema and queries
```

## Commands

| Command | What it does |
|---------|-------------|
| `pnpm dev` | Start dev mode (hot reload frontend + Rust backend) |
| `pnpm build` | Build release binary |
| `pnpm lint` | Run eslint on frontend |
| `pnpm format` | Run prettier on frontend |

## License

MIT
