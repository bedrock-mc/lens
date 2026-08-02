# Bedrock Lens

Bedrock Lens builds a versioned, evidence-backed index of Minecraft Bedrock binaries. It transfers
knowledge from symbol-rich BDS builds into stripped server and client builds using Ghidra and BSim.

## What works

- Registers PE artifacts by SHA-256, release, channel, and client/server role.
- Extracts PE architecture, image base, timestamp, image size, and exact RSDS/PDB identity.
- Runs persistent, SHA-keyed Ghidra analysis through native CPython with PyGhidra.
- Runs persistent headless IDA Pro analysis and Hex-Rays decompilation when IDA is installed.
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

Lens uses Python 3.12. Ghidra 12 or newer must be installed for the default backend. Lens discovers
Homebrew Ghidra and `ghidraRun` automatically; otherwise set `GHIDRA_INSTALL_DIR` or pass
`--ghidra-install`. IDA support requires a licensed IDA Pro installation with the Hex-Rays
decompiler; Lens discovers `idat`/`idat64` on `PATH`, otherwise set `IDA_INSTALL_DIR` or pass
`--ida-install` (the conventional `IDADIR` environment variable is also accepted).

## Reproducible corpus acquisition

The packaged manifest contains x64 Windows client packages for 1.16.201.2 and 1.20.40.1, plus the
current x64 Windows BDS package (1.26.36.1 at the time of writing). It stores no Minecraft
binaries: `lens` resolves Microsoft Store identities for the clients and the official Minecraft
download API for BDS, downloads each package, verifies its SHA-256, extracts the exact executable,
verifies its PE architecture and PDB identity, and then registers it in the catalog. The first
download is large; subsequent runs reuse the content-addressed cache.

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

The packaged BDS entry is zero-configuration: `lens corpus sync` asks the official Minecraft
download API for the stable Windows link, then verifies it against the manifest's pinned archive,
executable, and PDB identities. If Mojang publishes a new BDS build, synchronization fails closed
until the manifest is updated with the new version and hashes; an existing cache remains
reproducible. Custom manifests can use `type = "bds_latest"` with `platform = "windows"` or
`"linux"`, or a direct `type = "url"` for a historically pinned URL. The official download page is
[Minecraft Bedrock Server Download](https://www.minecraft.net/en-us/download/server/bedrock).

## End-to-end workflow

Use one SQLite catalog, one analysis project directory, and one BSim database for Ghidra corpus
matching:

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

Select IDA for function/string evidence and Hex-Rays decompilation:

```bash
uv run lens --database .lens/lens.db analyze 1 \
  --backend ida \
  --ida-install /path/to/ida \
  --project-dir .lens/ida-projects

uv run lens --database .lens/lens.db decompile 1 0x1870c60 \
  --backend ida \
  --ida-install /path/to/ida \
  --project-dir .lens/ida-projects
```

Ghidra and IDA databases are keyed by executable SHA-256, so rerunning analysis reuses the saved
program. BSim is a Ghidra feature and remains unavailable for `--backend ida`.

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
artifact SHA-256, PE image base, version, role, analysis-backend version, and analysis run. BSim
results retain both similarity and significance so a candidate can be ranked without presenting it
as a verified semantic match. Final claims should additionally be confirmed through constants, call
sites, referenced strings, or decompiled control flow.
