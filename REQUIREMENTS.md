# Requirements & Installation

Ojuri runs on the **SANS SIFT Workstation out of the box** with zero external
dependencies. This document describes what is required to run it elsewhere
(Linux, Windows, macOS) and how to verify each component.

> Living document — updated as platform support and the dependency set change.
> Last updated: 2026-05-17.

---

## Quick start: SIFT Workstation

All required forensic tooling (`rip.pl`/RegRipper3, MFTECmd, `pyscca`,
`ewfmount`/libewf) is pre-installed on SIFT. Just:

```bash
git clone https://github.com/Dextan-solutions/ojuri.git
cd ojuri
python3 -m venv .venv --system-site-packages   # --system-site-packages so pyscca is visible
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest
```

`--system-site-packages` matters: `pyscca` is provided as a system package on
SIFT and is not pip-installable into an isolated venv there.

---

## Linux (non-SIFT: Ubuntu, Fedora, Debian, …)

### Required packages

- **Python 3.12+** (some distros default to older; install `python3.12`
  explicitly).
- **libewf-utils** (provides `ewfmount`) — needed for E01 evidence.
- **python3-pyscca** (libscca Python bindings) — Prefetch parsing.
- **RegRipper3** (`rip.pl` + Perl runtime) — registry autostarts.
- **MFTECmd** (.NET 8 runtime + the binary) — `$MFT` timeline.

### Installation

**Ubuntu / Debian:**

```bash
sudo apt install python3.12 libewf-utils python3-pyscca dotnet-runtime-8.0
git clone https://github.com/EricZimmerman/RegRipper3.git /opt/regripper
# MFTECmd: download the .NET build from the releases page and place it on PATH,
# or set OJURI_MFTECMD to its location.
wget -O /opt/mftecmd/MFTECmd https://github.com/EricZimmerman/MFTECmd/releases/...
```

**Fedora:**

```bash
sudo dnf install python3.12 libewf-tools python3-libscca dotnet-runtime-8.0
git clone https://github.com/EricZimmerman/RegRipper3.git /opt/regripper
# same MFTECmd step as above
```

### Verification

```bash
rip.pl -h                       # RegRipper present
python3 -c "import pyscca"      # libscca bindings importable
MFTECmd                         # prints usage banner
ewfmount -h                     # libewf FUSE mount present
```

Set `OJURI_RIP_PL`, `OJURI_MFTECMD` if the binaries are not on `PATH`.

---

## Windows

### Supported architecture

- **`rip.pl`** — requires Strawberry Perl (~80 MB install).
- **MFTECmd** — native Windows binary, no special runtime.
- **`pyscca`** — `pip install pyscca` works on Windows.
- **Evidence opening** — `ewfmount` is **Linux-only**. Windows alternatives:
  - Arsenal Image Mounter (commercial, ~$200/seat)
  - OSFMount (free, supports E01)
  - Manual: extract the volume with FTK Imager, point Ojuri at the extracted
    directory and skip Stage 1.

### Installation

- Strawberry Perl: https://strawberryperl.com/
- Python 3.12: python.org installer
- RegRipper3: clone `github.com/EricZimmerman/RegRipper3`; set `OJURI_RIP_PL`
- MFTECmd: download the `.exe` from `github.com/EricZimmerman/MFTECmd/releases`
- `pip install -r requirements.txt`
- Set `OJURI_EVIDENCE_OPENER="osfmount"` (or `arsenal`) once configured.

> Windows evidence opening is **not yet implemented** in `open_evidence.sh`;
> planned for v0.3. Today, use the manual FTK-extract path on Windows.

---

## macOS

### Supported architecture

- **`pyscca`** — `pip install pyscca` (needs Xcode command-line tools).
- **MFTECmd** — needs the .NET 8 runtime (`brew install dotnet`).
- **`rip.pl`** — Perl is preinstalled; add RegRipper3.
- **Evidence opening** — libewf via `brew install libewf` (provides
  `ewfmount` through macFUSE; macFUSE must be installed separately).

### Installation

```bash
brew install python@3.12 libewf dotnet
git clone https://github.com/EricZimmerman/RegRipper3.git /opt/regripper
# download + extract MFTECmd, chmod +x, set OJURI_MFTECMD
pip install -r requirements.txt
```

---

## Per-primitive platform support

| Primitive | Linux | macOS | Windows | External dependency |
|-----------|:-----:|:-----:|:-------:|---------------------|
| `list_evidence_artefacts` | ✓ | ✓ | ✓ | **None — Python stdlib only** |
| `get_registry_autostarts` | ✓ | ✓ | ✓ | RegRipper3 (`rip.pl`) |
| `get_user_autostarts` | ✓ | ✓ | ✓ | RegRipper3 (`rip.pl`) |
| `get_prefetch_entries` | ✓ | ✓ | ✓ | `pyscca` (libscca binding) |
| `get_mft_timeline` | ✓ | ✓ | ✓ | MFTECmd |

`list_evidence_artefacts` (the mandatory discovery primitive) uses **only the
Python standard library** (`os`, `pathlib`) — a pure, read-only filesystem
walk with **no subprocess and no external dependency**. It therefore runs
unmodified on **all platforms (Linux, macOS, Windows)** with nothing to
install. The only platform-specific gap remaining anywhere in Ojuri is WOF
content-baselining of reparse-point files on Linux (§ Troubleshooting / see
DECISIONS 2026-05-17 "WOF reparse-point clarification"); a future **native
Windows port** would close that gap by using the host kernel's WOF driver.

---

## Python dependencies

Pinned in [`requirements.txt`](./requirements.txt):

- `mcp==1.2.0`
- `pydantic>=2.5,<3.0`
- `pytest>=8.0` (test-only)

`pyscca` is intentionally **not** in `requirements.txt`: on SIFT it is a system
package (hence `--system-site-packages`); on other platforms it is installed per
the OS sections above.

---

## System requirements

- **Disk:** ≥ 30 GB free for a case image + scratch space (a single C-drive E01
  is ~20–25 GB; the loop-mount needs no extra copy, but baselines and analysis
  output do).
- **Memory:** 8 GB minimum; 16 GB recommended for large `$MFT` parsing.
- **Network:** outbound HTTPS only, for MCP server registration with Claude
  Code. No inbound exposure; evidence never leaves the host.

---

## Optional dependencies

- **pandoc** — markdown → `.docx` for the submission deliverable
  (see [docs/architecture/SOURCE_PROMPT.md](./docs/architecture/SOURCE_PROMPT.md)).
- **libreoffice** (`soffice`) — layout verification and PDF sanity render.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ewfmount: command not found` | Install `libewf-utils` (Linux) / `brew install libewf` (macOS); Windows uses OSFMount/Arsenal |
| `python3-pyscca not found` (Ubuntu) | Repository gap — build libscca from source per its README, or use `--system-site-packages` against a system install |
| `rip.pl not found` | Set `OJURI_RIP_PL` to the RegRipper3 `rip.pl` path |
| `MFTECmd: command not found` | Set `OJURI_MFTECMD`; ensure the binary is executable (`chmod +x`) |
| `pytest` import errors for `pyscca` in venv | Recreate the venv with `--system-site-packages` |
| Mount fails with "already mounted" | `sudo umount /evidence/<case>` (and the `/var/lib/ojuri/...` stages) before re-running the opener |
| Permission denied during mount | Run `open_evidence.sh` with `sudo` (mounting is privileged) |

---

## Roadmap

- **v0.3:** native E01 support on Windows (Arsenal / OSFMount integration in
  `open_evidence.sh`).
- **v0.4:** AFF4 support.
- **v0.5:** VMDK / VHDX support.

See [docs/architecture/ARCHITECTURE.md §12](./docs/architecture/ARCHITECTURE.md)
for the full roadmap.
