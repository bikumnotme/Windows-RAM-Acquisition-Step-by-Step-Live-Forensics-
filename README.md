# Windows RAM Acquisition — Step-by-Step (Live Forensics)

**Goal:** Acquire a defensible memory image from a Windows host, with minimal footprint, full integrity controls (hashes), and a complete Chain-of-Custody (CoC).  
**Scope:** Windows 10/11 (x64) primarily; notes for Secure Boot, EDR/AV, and file system limits.  
**Principle:** _Volatile-first_ (ưu tiên dữ liệu dễ bay hơi), _work-on-copy_ (làm việc trên bản sao), UTC timestamps, and two-artefact corroboration in the report.

---

## 0) Pre-acquisition Checklist (Quick)

- **Authority & scope** documented (legal/IR ticket).  
- **Admin rights** available on target (local Administrator or equivalent).  
- **External media**: trusted USB (NTFS/exFAT; enough free space for RAM size).  
- **Hashing tool** available: PowerShell `Get-FileHash` is sufficient.  
- **Tool choice** (prefer a **signed driver** on Secure Boot systems):
  - **WinPMEM (AFF4/RAW)** — commonly used; ensure a signed build.
  - **DumpIt** (raw, very simple), **Magnet RAM Capture**, **Belkasoft RAM Capturer** (GUI, signed).

> **Secure Boot:** Unsigned kernel drivers will fail to load. Use a tool that ships with a **signed** driver (e.g., Magnet/Belkasoft, or a signed WinPMEM build). Avoid disabling Secure Boot in the field.

---

## 1) Prepare Evidence Workspace & Start Transcript

On the **target** machine (logged in as admin), open **PowerShell (Run as Administrator)**:

```powershell
# Create evidence folder on external USB (adjust drive letter)
$ev = "E:\case123_hostA_ram"
New-Item -ItemType Directory -Force -Path $ev | Out-Null

# Start a text transcript for CoC and command logging (UTC)
$transcript = Join-Path $ev "00_transcript.txt"
Start-Transcript -Path $transcript -Force
Get-Date -AsUTC | Out-File (Join-Path $ev "00_utc_start.txt")

# Record quick host facts
systeminfo | Out-File (Join-Path $ev "01_systeminfo.txt")
wmic os get osarchitecture /value | Out-File (Join-Path $ev "01_osarch.txt")
Get-ComputerInfo | Out-File (Join-Path $ev "01_compinfo.txt")
```

> Keep the transcript running until the end. Avoid launching heavy apps.

---

## 2) Option A — WinPMEM (AFF4 preferred)

**Why:** Produces **AFF4** (compressed, sparse-friendly) or RAW. CLI control, widely used in DFIR.  
**Prereq:** Use a **signed** WinPMEM build on Secure Boot systems.

1) **Stage the binary** (from your trusted USB) to a temp location (optional):

```powershell
Copy-Item "E:\tools\winpmem\winpmem_x64.exe" "$env:TEMP\winpmem.exe"
Get-ChildItem "$env:TEMP\winpmem.exe" | Format-List * | Out-File (Join-Path $ev "02_tool_listing.txt")
```

2) **Acquire to AFF4** (recommended) **or** RAW:

```powershell
# AFF4 (recommended): smaller, preserves metadata
& "$env:TEMP\winpmem.exe" --format aff4 --output (Join-Path $ev "mem.aff4")

# Or RAW (very large file, equals RAM size)
# & "$env:TEMP\winpmem.exe" --format raw --output (Join-Path $ev "mem.raw")
```

3) **Hash the image** and record tool signature info:

```powershell
Get-FileHash (Join-Path $ev "mem.aff4") -Algorithm SHA256 | Tee-Object -FilePath (Join-Path $ev "03_hash_after.txt")
Get-Item "$env:TEMP\winpmem.exe" | Format-List * | Out-File (Join-Path $ev "02_tool_file_meta.txt")

# (Optional) capture Authenticode signature of the tool binary
Get-AuthenticodeSignature "$env:TEMP\winpmem.exe" | Format-List * | Out-File (Join-Path $ev "02_tool_signature.txt")
```

4) **Stop transcript** and capture end UTC:

```powershell
Get-Date -AsUTC | Out-File (Join-Path $ev "00_utc_end.txt")
Stop-Transcript
```

**Expected outputs:** `mem.aff4` (or `mem.raw`), hash file, transcript, UTC markers, host facts, tool metadata.

---

## 3) Option B — DumpIt (Raw; Very Simple)

**Why:** Minimal interaction; produces a RAW dump. Good fallback when a signed WinPMEM is unavailable.

1) Run `DumpIt.exe` as **Administrator** from your trusted USB.  
2) Follow the prompt (press `Y`) — choose output folder on your evidence drive (e.g., `E:\case123_hostA_ram`).  
3) When it finishes, **hash** the output:

```powershell
Get-FileHash "E:\case123_hostA_ram\memory.raw" -Algorithm SHA256 | Out-File "E:\case123_hostA_ram\03_hash_after.txt"
```

4) Save any logs/files created by the tool into the evidence folder.

---

## 4) Option C — Magnet RAM Capture / Belkasoft RAM Capturer (GUI)

**Why:** Both ship with **signed drivers**; work reliably on Secure Boot systems.

**Magnet RAM Capture (MRC)** (GUI):
1) Launch `MagnetRAMCapture.exe` as Administrator.  
2) Select output location on your evidence drive (e.g., `E:\case123_hostA_ram\mem_mrc.raw`).  
3) Start capture; wait for completion.  
4) Hash the file in PowerShell:

```powershell
Get-FileHash "E:\case123_hostA_ram\mem_mrc.raw" -Algorithm SHA256 | Out-File "E:\case123_hostA_ram\03_hash_after.txt"
```

**Belkasoft RAM Capturer (BRC)** is similar: run as admin, select output, capture, then hash.

> **Tip:** Avoid saving to FAT32 (4 GB file size limit). Use NTFS/exFAT on your USB.

---

## 5) Optional: Collect Pagefile & Hibernation Artifacts

These can contain memory artefacts:

- **pagefile.sys** (paged memory), **hiberfil.sys** (if hibernation/fast startup).  
- Acquire via **VSS snapshot** to avoid locks:

```powershell
# Create a shadow copy, then copy artefacts from the shadow path
vssadmin create shadow /for=C:
# Find the shadow path (use 'vssadmin list shadows'), then:
Copy-Item "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\pagefile.sys" "E:\case123_hostA_ram\pagefile.sys"
Copy-Item "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\hiberfil.sys" "E:\case123_hostA_ram\hiberfil.sys"

Get-FileHash "E:\case123_hostA_ram\pagefile.sys" -Algorithm SHA256 | Out-File "E:\case123_hostA_ram\03_hash_pagefile.txt"
Get-FileHash "E:\case123_hostA_ram\hiberfil.sys" -Algorithm SHA256 | Out-File "E:\case123_hostA_ram\03_hash_hiberfil.txt"
```

Document the exact shadow ID and commands in your CoC.

---

## 6) Integrity & Chain-of-Custody (CoC)

**Immediately after acquisition:**
- Hash the memory image(s) **again** on the analysis workstation to confirm same hash.
- Record **who/when/where** (UTC), tool & version, paths, and media IDs/serials.
- Package deliverables on read-only media (or write-protected storage).

**Minimal CoC template (fill during the operation):**
```
Case ID: __________________________
Evidence ID/Label: ________________
Host name: ________________________
OS/Arch: __________________________
Physical Location: ________________

Action: RAM acquisition
Date/Time (UTC): __________________
Examiner: _________________________
Tool & Version: ___________________
Driver signature (if applicable): _
Source Media (make/model/serial): _
Output Path: ______________________
Hash (SHA-256): ___________________

Transfer to: ______________________
Date/Time (UTC): __________________
Seal/Bag #: _______________________
Conditions/Notes: _________________
```

Save as `00_coc.txt` inside your evidence folder.

---

## 7) Quick Triage (Optional) — Volatility 3

On the **analysis** machine:

```bash
# Example using Volatility 3 (Python)
vol.py -f mem.aff4 windows.info > v3_info.txt
vol.py -f mem.aff4 windows.pslist > v3_pslist.txt
vol.py -f mem.aff4 windows.netscan > v3_netscan.txt
vol.py -f mem.aff4 windows.malfind > v3_malfind.txt
```

> Keep analysis read-only; write results to a new directory. Normalize times to UTC for timeline joins.

---

## 8) Troubleshooting & Pitfalls

- **Secure Boot blocks driver**: choose a tool with a **signed** driver (Magnet/Belkasoft, signed WinPMEM).  
- **EDR/AV interferes**: capture exception in the IR ticket; use approved toolkit; preserve logs of any blocks.  
- **Disk full / file too large**: RAM size can be tens of GB; ensure destination is NTFS/exFAT with free space > RAM size.  
- **System instability**: don’t run heavy apps or open GUIs; perform the minimum needed.  
- **Timezone confusion**: stamp everything twice (local and UTC) and normalize to UTC in reports.  

---

## 9) Deliverables (What to Turn In)

- Memory image: `mem.aff4` (or `mem.raw`) + **SHA-256 hash**.  
- Transcript (`00_transcript.txt`), UTC start/end markers, host facts (`01_*`).  
- CoC file (`00_coc.txt`) completed and signed.  
- (Optional) `pagefile.sys`, `hiberfil.sys` + hashes.  
- Any tool logs / signatures (`02_tool_*`).

---

### One-Command Recap (WinPMEM + Hash)

```powershell
$ev="E:\case123_hostA_ram"; New-Item -ItemType Directory -Force -Path $ev | Out-Null
Start-Transcript -Path (Join-Path $ev "00_transcript.txt") -Force
& "E:\tools\winpmem\winpmem_x64.exe" --format aff4 --output (Join-Path $ev "mem.aff4")
Get-FileHash (Join-Path $ev "mem.aff4") -Algorithm SHA256 | Out-File (Join-Path $ev "03_hash_after.txt")
Stop-Transcript
```

> Replace `E:\tools\winpmem\winpmem_x64.exe` with your actual tool path. Keep all outputs in the evidence folder and copy to read-only media.
