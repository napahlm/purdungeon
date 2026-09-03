default:
    @just --list

dev:
    pnpm tauri dev

build:
    pnpm tauri build

# Everything CI runs, in one go.
ci: lint test deny

test:
    cargo test --workspace

lint:
    pnpm eslint src/
    cargo clippy --workspace --all-targets -- -D warnings

format:
    pnpm prettier --write "src/**/*.{ts,vue,css,json}"
    cargo fmt --all

check:
    cargo check --workspace --all-targets

# Licence and dependency policy from deny.toml (needs `cargo install cargo-deny`).
deny:
    cargo deny check licenses bans sources

# Download the fetch-only test corpus listed in crates/core/tests/corpus/manifest.toml.
fetch-corpus:
    cargo run -p xtask -- fetch-corpus

# Rewrite the golden snapshots after an intended behaviour change, then review the diff.
golden-update:
    UPDATE_GOLDEN=1 cargo test -p purdungeon-core --test golden

# Check the fetched corpus against its committed snapshots (release build: the files are large).
golden-corpus:
    cargo test --release -p purdungeon-core --test golden -- --ignored golden_corpus

golden-corpus-update:
    UPDATE_GOLDEN=1 cargo test --release -p purdungeon-core --test golden -- --ignored golden_corpus

clean:
    cargo clean
    rm -rf dist node_modules/.vite
