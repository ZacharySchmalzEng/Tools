# Data_Management — Windows

This folder contains scripts and utilities for safely inspecting, merging, and deduplicating user data across NTFS volumes and backups.

## Contents

- `ProfileMerge.ps1` — Heuristic discovery and deduplication engine for cross-OS user profiles. Scans NTFS volumes, generates a declarative CSV state-plan, and assists with safe merges using SHA-256 hashing to identify true duplicates.

## Purpose

Provide a repeatable, auditable workflow to reconcile scattered user profile data, reduce duplication, and prepare a safe merge plan that can be reviewed before execution.

## Prerequisites

- PowerShell 7+ recommended (works in Windows PowerShell but some features may vary)
- Run with Administrator privileges to access all NTFS metadata and volume-level information

## Usage

1. Inspect the script and run a read-only discovery pass to generate the CSV plan:

```powershell
.\ProfileMerge.ps1 -Mode Discover -Output plan.csv
```

2. Review `plan.csv` carefully. The tool is designed to be idempotent and conservative; manual review is recommended prior to any merge or delete steps.

3. When ready, run an execution mode that performs merges according to the plan:

```powershell
.\ProfileMerge.ps1 -Mode Execute -Plan plan.csv
```

## Safety & Audit

- Always operate on read-only copies or snapshots when possible. For live systems, ensure you have full backups before making destructive changes.
- The script emits a declarative CSV state-plan so changes can be reviewed and reverted if needed.

## Notes

- Designed to be conservative: duplicates are identified via cryptographic hashing and size heuristics, and candidate merges require explicit confirmation when run in interactive mode.
- For large volumes, initial discovery may take time; consider excluding known large media folders if not relevant.
