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



# RAM Forensics Lab — Emergency Scenario (Ransomware Case) — **Final Student Guide**

*English with key Vietnamese terms in parentheses.*

**Scope:** Emergency **dead acquisition** & forensic analysis for ransomware incidents when only system swap/suspend artefacts are available (no live RAM capture).  
**Tooling:** Volatility 3, MemProcFS, standard OS utilities (Windows `certutil`, PowerShell `Get-FileHash`, Linux `sha256sum`).  
**Primary artefacts:** `hiberfil.sys` (Windows hibernation file), `pagefile.sys` (Windows paging file).

**Workflow:** 1) Suspend → 2) Acquire `.sys` artefacts (read-only) → 3) Hash → 4) Convert/prepare RAM image → 5) Analyse (Volatility 3 + MemProcFS) → 6) Extract artefacts → 7) Document & Chain of Custody (CoC).

---

## 0) Learning Outcomes (Mục tiêu)

Students will be able to:

- Preserve volatile state by **Sleep/Hibernate** instead of power-off.
- Perform **dead acquisition** of `hiberfil.sys` and `pagefile.sys` with read-only mounting.
- Compute and record **SHA‑256** hashes for integrity assurance.
- Convert **hibernation data** into a RAW memory image using **Volatility 3**.
- Analyse the resulting memory with **Volatility 3** and **MemProcFS**.
- Extract ransomware indicators (processes, injected code, dropped files, network sockets).
- Maintain detailed **Evidence Log** and **Chain of Custody**.

---

## 1) Emergency Response (Xử lý khẩn cấp)

- **Do NOT power off** the compromised system (shutdown clears RAM).  
- Use **Sleep** (short-term, RAM retained with power) or **Hibernate** (longer retention to disk via `hiberfil.sys`).  
- Rationale: Ransomware often holds keys, injects code, or runs in memory; suspension preserves artefacts for analysis.

---

## 2) Acquire RAM Artefacts (Thu thập tệp hệ thống) — *Dead acquisition only*

Choose **one** path based on your boot environment. Always mount the Windows volume **read-only**.

### 2.1 Windows Live (WinPE / Forensic Boot USB)

1. Boot with a **trusted WinPE** forensic USB. Launch *Command Prompt (Admin)*.  
2. Identify Windows volume (e.g., `C:`) and evidence drive (e.g., `E:`).  
3. Copy hidden system files while preserving metadata:

   ```cmd
   xcopy /h /k /o /x C:\hiberfil.sys E:\EmergencyCase\hiberfil.sys
   xcopy /h /k /o /x C:\pagefile.sys E:\EmergencyCase\pagefile.sys
   ```

   Flags: `/h` include hidden/system, `/k` keep attributes, `/o` ACLs, `/x` audit.
4. Hash for integrity:

   ```cmd
   certutil -hashfile E:\EmergencyCase\hiberfil.sys SHA256
   certutil -hashfile E:\EmergencyCase\pagefile.sys  SHA256
   ```

5. Save outputs and hashes in **Evidence Log**.

### 2.2 Ubuntu Live USB (Forensic Mode)

1. Boot **Ubuntu live** → *Try Ubuntu*. Open Terminal.  
2. Find the Windows partition:

   ```bash
   sudo fdisk -l
   ```

3. Mount **read‑only** and mount an **evidence drive** read‑write:

   ```bash
   sudo mkdir -p /mnt/win /mnt/evidence
   sudo mount -o ro /dev/sda2 /mnt/win              # adjust device
   sudo mount /dev/sdb1 /mnt/evidence               # your evidence USB
   ```

4. Copy artefacts, preserving metadata:

   ```bash
   sudo cp -a /mnt/win/hiberfil.sys /mnt/evidence/EmergencyCase/
   sudo cp -a /mnt/win/pagefile.sys /mnt/evidence/EmergencyCase/
   ```

5. Hash for integrity:

   ```bash
   sha256sum /mnt/evidence/EmergencyCase/hiberfil.sys              /mnt/evidence/EmergencyCase/pagefile.sys | tee /mnt/evidence/EmergencyCase/hashes.txt
   ```

### 2.3 Ubuntu Dual Boot (Lab Environment)

1. Boot into **Ubuntu**. List partitions and identify NTFS:

   ```bash
   sudo lsblk -f
   ```

2. Mount **read‑only**:

   ```bash
   sudo mkdir -p /mnt/win
   sudo mount -o ro /dev/sda3 /mnt/win              # adjust device
   ```

3. Copy to student home evidence folder:

   ```bash
   mkdir -p ~/Forensics/EmergencyCase
   sudo cp -a /mnt/win/hiberfil.sys ~/Forensics/EmergencyCase/
   sudo cp -a /mnt/win/pagefile.sys ~/Forensics/EmergencyCase/
   ```

4. Hash and log:

   ```bash
   cd ~/Forensics/EmergencyCase
   sha256sum hiberfil.sys pagefile.sys | tee hashes.txt
   ```

> **Note:** If `hiberfil.sys` is missing, hibernation may be disabled or an alternative sleep mechanism is used. Proceed with `pagefile.sys` triage and any crash dumps if present.

---

## 3) Convert / Prepare a RAW Memory Image

**Goal:** Derive a usable RAM image from `hiberfil.sys` for analysis in Volatility 3 and MemProcFS.

### 3.1 Inspect Hibernation Metadata (Volatility 3)

```powershell
python vol.py -f E:\EmergencyCase\hiberfil.sys windows.hibernationinfo
```

### 3.2 Dump Memory Contents From Hibernation (Volatility 3)

```powershell
python vol.py -f E:\EmergencyCase\hiberfil.sys windows.hibernation --dump -o E:\EmergencyCase\dump_from_hiber
```

This produces one or more memory segment dumps under `dump_from_hiber\`. If a single combined RAW is produced (e.g., `memory.raw`), use that file in subsequent steps. Otherwise, prioritise the largest segment for triage and document any limitations.

### 3.3 Pagefile Triage (Optional but Recommended)

- Quick triage:

  ```bash
  strings E:\EmergencyCase\pagefile.sys > E:\EmergencyCase\pagefile_strings.txt
  ```

- YARA scan for ransomware markers (use your team’s ruleset).

Hash **all** generated outputs and add entries to the Evidence Log.

---

## 4) Analysis — Volatility 3

Assume your RAW image is `E:\EmergencyCase\mem_ransom_hiber.raw` (or the largest segment from step 3.2).

### 4.1 System & Process Recon

```powershell
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.info
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.pslist
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.pstree
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.psscan
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.handles
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.svcscan
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.getsids
```

### 4.2 Malware Indicators & Artefacts

```powershell
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.malfind --dump -o E:\EmergencyCase\extracts\malfind
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.cmdline
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.netscan
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.filescan
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.vadinfo
```

> Tip: Correlate suspicious PIDs across `malfind`, `vadinfo`, `handles`, and `netscan` to build a strong narrative.

### 4.3 Targeted Extraction (example with PID 1234)

```powershell
# Create output folders
New-Item -ItemType Directory E:\EmergencyCase\extracts\pid1234 -Force | Out-Null

# Dump process memory regions
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.vaddump --pid 1234 -o E:\EmergencyCase\extracts\pid1234

# Dump dropped files found in memory
python vol.py -f E:\EmergencyCase\mem_ransom_hiber.raw windows.dumpfiles -o E:\EmergencyCase\extracts\dumpfiles
```

Hash each extracted artefact (`SHA-256`) and log the values.

---

## 5) Analysis — MemProcFS

**Mount** the memory image as a virtual filesystem and browse artefacts as files/folders.

```powershell
MemProcFS.exe -device E:\EmergencyCase\mem_ransom_hiber.raw -forensic 1 -o E:\EmergencyCase\memproc_mount
```

Explore:

- `processes\` → process address spaces (look for ransomware PID).
- `modules\` → DLLs; check unsigned/odd paths.
- `cmdline.txt` → historical command lines.
- `sockets\` → IPv4/6 connections for suspected C2.
- `yara\` → run built-in or custom rules.

Copy out suspicious items to `E:\EmergencyCase\extracts\...` and hash them.

---

## 6) Documentation & Chain of Custody (Ghi chép & CoC)

### 6.1 Evidence Logbook (Sổ chứng cứ)

Record for each artefact/dump:

- Case ID, Examiner, System identifiers, Date/Time (UTC+7).  
- Acquisition source/path, exact commands used, **SHA‑256** hash.  
- Analysis steps performed (plugin names, filter parameters), findings summary.  
- Extracted artefacts: file path, size, hash, related PID/indicator.

### 6.2 Chain of Custody Table

| Evidence ID | Case ID | Description | Acquired By | Date/Time | Location | SHA-256 | Released To | Signature |
|---|---|---|---|---|---|---|---|---|
| EV-H1 | RANSOM2025 | `hiberfil.sys` (dead acquisition) | <Name> | <UTC+7> | USB SN:XXX | `<hash>` | <TA> | ___ |
| EV-P1 | RANSOM2025 | `pagefile.sys` (dead acquisition) | <Name> | <UTC+7> | USB SN:XXX | `<hash>` | <TA> | ___ |
| EV-R1 | RANSOM2025 | RAW memory from hibernation | <Name> | <UTC+7> | HDD | `<hash>` | <TA> | ___ |
| EV-X* | RANSOM2025 | Extracted artefacts (PID folders, dumpfiles) | <Name> | <UTC+7> | HDD | `<hash>` | <TA> | ___ |

> Keep physical media labeled, sealed, and documented at each transfer.

---

## 7) Deliverables (Nộp bài)

- `hiberfil.sys`, `pagefile.sys` copies + **hashes**.  
- RAW memory image(s) derived from hibernation + **hashes**.  
- Volatility 3 output logs and CSVs (process lists, scans, dumps).  
- MemProcFS extracted items and notes.  
- Lab report (Evidence Log + CoC attached).

---

## 8) Troubleshooting & Notes

- **`hiberfil.sys` parsing fails:** ensure correct file; try a different Volatility 3 build. Prioritise largest dumped segment for analysis.
- **BitLocker/Full‑disk encryption:** you must access the unlocked Windows partition (e.g., via proper credentials or recovery mode) before copying files.
- **Huge artefacts:** copy with `robocopy` (Windows) or `rsync` (Linux) and verify hashes.
- **Hash mismatch:** re-copy from original; check USB health; verify no AV/auto‑repair touched the files.
- **Time context:** Hibernation captures state at suspend time, not necessarily at infection time. Interpret accordingly.

---

## 9) Student Checklist

- [ ] Suspended affected PC (sleep/hibernate)  
- [ ] Mounted Windows partition **read-only**  
- [ ] Copied `hiberfil.sys` and `pagefile.sys` to evidence storage  
- [ ] Computed and recorded SHA‑256 hashes  
- [ ] Converted hibernation to RAW memory  
- [ ] Analysed with Volatility 3 + MemProcFS  
- [ ] Extracted and hashed target artefacts  
- [ ] Completed Evidence Logbook + CoC  

---

## Appendix A — Example YARA (optional)

```yara
rule Possible_Ransomware_Dropper {
  meta:
    author = "IR Lab"
    description = "Generic strings seen in ransomware droppers"
  strings:
    $s1 = "vssadmin delete shadows" nocase
    $s2 = "bcdedit /set {default} recoveryenabled no" nocase
    $s3 = "wmic shadowcopy delete" nocase
  condition:
    any of ($s*)
}
```

## Appendix B — Reporting Template (trích yếu)

**Executive Summary:**  

- Incident synopsis, timeline, key indicators, scope of encryption.

**Findings:**  

- Suspicious PIDs & modules; injected regions; dropped files; network endpoints.

**Impact & Risk:**  

- Data at risk, lateral movement indicators, persistence mechanisms.

**Recommendations:**  

- Containment, eradication, recovery steps; hardening; user education.
