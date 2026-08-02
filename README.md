# Bedrock Lens

Bedrock Lens builds a versioned, evidence-backed index of Minecraft Bedrock binaries. It transfers
knowledge from symbol-rich BDS builds into stripped server and client builds using Ghidra and BSim.

## What works

- Registers PE artifacts by SHA-256, release, channel, and client/server role.
- Extracts PE architecture, image base, timestamp, image size, and exact RSDS/PDB identity.
- Runs persistent, SHA-keyed Ghidra analysis through native CPython with PyGhidra.
- Indexes function names, namespaces, sizes, parameters, and referenced strings in SQLite.
- Searches symbols and strings across every indexed version.
- Decompiles a selected function on demand.
- Builds a persistent Ghidra BSim index and finds structurally similar functions across binaries.
- Records the Ghidra version and success/failure of every analysis run.
- Fetches a pinned corpus from Microsoft delivery services, verifies archive and PE hashes, and
  registers extracted artifacts automatically.

## Setup

Python and dependencies are managed entirely by `uv`:

```bash
uv sync --extra analysis
uv run lens --help
```

Lens uses Python 3.12. Ghidra 12 or newer must be installed. Lens discovers Homebrew Ghidra and
`ghidraRun` automatically; otherwise set `GHIDRA_INSTALL_DIR` or pass `--ghidra-install`.

## Reproducible corpus acquisition

The packaged manifest contains the x64 Windows client packages for 1.16.201.2 and 1.20.40.1.
It stores no Minecraft binaries: `lens` resolves the Microsoft Store update identity, downloads
the package, verifies its SHA-256, extracts the exact executable, verifies its PE architecture and
PDB identity, and then registers it in the catalog. The first download is large; subsequent runs
reuse the content-addressed cache.

```bash
# See the immutable entries shipped with Lens.
uv run lens corpus list

# Fetch one version (recommended when starting out).
uv run lens --database .lens/lens.db fetch client-1.20.40.1-x64

# Fetch and register every entry in a custom or packaged manifest.
uv run lens --database .lens/lens.db corpus sync

# Put the cache somewhere shared by multiple catalogs or machines.
uv run lens --database .lens/lens.db fetch client-1.16.201.2-x64 \
  --cache-dir /path/to/bedrock-lens-cache
```

The default cache is `~/.cache/bedrock-lens` (or `$XDG_CACHE_HOME/bedrock-lens`). It contains
`blobs/sha256/<archive hash>` and extracted `artifacts/sha256/<binary hash>/...`; it is safe to
delete and rebuild. Store package resolution uses update identities maintained by
[mc-w10-versiondb-auto-update](https://github.com/ddf8196/mc-w10-versiondb-auto-update). You must
own the relevant Minecraft package and comply with Microsoft/Mojang terms; Lens does not bypass
Store entitlement checks or redistribute packages.

For BDS, use the same manifest format with a direct official URL, the expected archive SHA-256,
and `member = "bedrock_server.exe"` (or `bedrock_server` for Linux). Historical BDS URLs are not
published as a stable official index, so they should be pinned by the project that records them;
Lens will reject a changed archive rather than silently accepting a replacement. The current
official download page is [Minecraft Bedrock Server Download](https://www.minecraft.net/en-us/download/server/bedrock).

## End-to-end workflow

Use one SQLite catalog, one Ghidra project directory, and one BSim database for the corpus:

```bash
uv run lens --database .lens/lens.db add /binaries/1.20.40/bedrock_server.exe \
  --version 1.20.40.1 --kind server

uv run lens --database .lens/lens.db add /binaries/1.20.40/Minecraft.Windows.exe \
  --version 1.20.40.1 --kind client

uv run lens --database .lens/lens.db analyze 1 \
  --project-dir .lens/ghidra-projects \
  --bsim-database .lens/bsim/lens

uv run lens --database .lens/lens.db analyze 2 \
  --project-dir .lens/ghidra-projects \
  --bsim-database .lens/bsim/lens
```

Ghidra projects are keyed by executable SHA-256, so rerunning analysis reuses the saved program.
BSim also safely skips binaries already present in its index.

Search the symbol-rich BDS artifact:

```bash
uv run lens --database .lens/lens.db search crossbow
```

Take an RVA from the result and ask BSim for corresponding functions across the corpus:

```bash
uv run lens --database .lens/lens.db match 1 0x1870c60 \
  --project-dir .lens/ghidra-projects \
  --bsim-database .lens/bsim/lens \
  --min-similarity 0.7
```

Matches include the target artifact ID, Minecraft version, target RVA, BSim similarity, and BSim
significance whenever the executable belongs to the Lens catalog. Decompile a candidate directly:

```bash
uv run lens --database .lens/lens.db decompile 2 0x32a7840 \
  --project-dir .lens/ghidra-projects
```

All command output is JSON so results can be inspected manually or fed into later automation.

## Evidence model

An address alone is never treated as portable evidence. Lens associates every result with the
artifact SHA-256, PE image base, version, role, Ghidra version, and analysis run. BSim results retain
both similarity and significance so a candidate can be ranked without presenting it as a verified
semantic match. Final claims should additionally be confirmed through constants, call sites,
referenced strings, or decompiled control flow.
