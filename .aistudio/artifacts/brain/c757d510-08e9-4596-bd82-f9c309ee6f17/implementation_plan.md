# Script Documentation & Hardening Flag Search Index Plan

A comprehensive plan to build an instant search index inside the `ScriptInspector` component, enabling administrators to search across deployment flags, security hardening modules, key features, and technical documentation with real-time keyword highlighting and active vs. catalog-wide scope toggling.

---

### User Review & Critical Decisions

> [!IMPORTANT]
> **Confirmed User Decisions (from Phase 1 Clarifications)**:
> 1. **Search Scope**: Search within the **active script** by default, with an instant toggle switch to expand the index **catalog-wide across all scripts**.
> 2. **Indexed Content Domain**: Indexes all **command-line flags**, **security hardening modules & CVE controls**, **key engineering features**, and **architectural documentation**.
> 3. **Presentation & UX**: A **real-time filter bar** embedded directly above the inspector content area with **highlighted keyword matches** and categorical filtering.

---

### 1. Overview & Core Concept

- **What It Does**: Provides a dedicated, high-speed client-side search engine within `ScriptInspector`. As users type keywords (e.g., `"harden"`, `"2fa"`, `"cve"`, `"gaming"`, `"ssh"`, `"auditd"`, `"backup"`, `"restic"`), the index immediately filters and displays matching flags, security modules, and architectural features, highlighting the query substring in context.
- **Target Audience / Persona**: System administrators and security engineers who need to quickly locate the exact CLI syntax, safety prerequisites, elevated privileges, and package dependencies for a specific deployment flag or hardening control.
- **Key Value**: Eliminates manual scanning through hundreds of lines of documentation or code comments, providing single-click simulation runs and copy actions directly from matched results.

---

### 2. User Experience & Visual Design

#### Key User Flows
1. **Keyword Filtering Flow**:
   - The user navigates to the **Script Inspector** tab.
   - An expanded search toolbar appears above the Documentation and Flags views.
   - The user enters a search term (e.g., `harden`).
   - The index immediately surfaces matching items:
     - Flag `--harden` (Safe Baseline Hardening)
     - Flag `--harden-advanced` (Strict Zero-Trust Posture & auditd rules)
     - Documentation sections covering CIS Level 2 sysctl hardening and audit rules.
   - The search query substring is highlighted with a clean, high-contrast cyan background (`bg-cyan-500/20 text-cyan-200 rounded px-0.5`).
2. **Catalog-Wide Exploration Flow**:
   - The user toggles the scope switch from `"Active Script"` to `"All Catalog Scripts"`.
   - Results show matching flags and modules from `Windows-Deployment-Tool.ps1`, `Restic-Cloud-Backup.sh`, `SteamOS-Deck-Optimizer.sh`, and `Linux-Deployment-Tool.sh`.
   - Clicking a result from another script instantly switches the active inspector script and jumps directly to that flag or module.
3. **Action Integration**:
   - Each search result card includes direct action buttons:
     - **Copy Flag** (e.g., `navigator.clipboard.writeText('--harden-advanced')`)
     - **Run in Simulator** (transfers script and selected flag directly into `TerminalSimulator`)
     - **Inspect in Source** (switches to Code view and scrolls/highlights matching line)

#### Visual Identity & Theme
- **Search Bar**: Sleek input with left search icon, right clear `(✕)` button, active result count badge (e.g., `3 matches`), and scope toggle pill.
- **Color Distribution**:
  - Search container: Dark slate surface (`bg-slate-900 border border-slate-800`).
  - Active highlights: Crisp cyan (`bg-cyan-500/20 text-cyan-300`).
  - Security badges: Ruby/Rose for elevated/strict security (`bg-rose-950/60 text-rose-300 border-rose-800`).
- **Typography**: Tabular figures for line numbers and match counts (`font-mono tabular-nums`). Clean display sans for descriptions.

---

### 3. Key Product Decisions & Trade-Offs

- **Decision 1: Client-Side Pre-Indexed Data Model (`useMemo`)**
  - *Chosen Approach*: Index the structured `SCRIPT_CATALOG` metadata (`flags`, `keyFeatures`, `description`, `supportedDistrosOrEditions`) and combine it with script comment headers in memory using a reactive `useMemo` search index.
  - *Why*: Sub-millisecond response time with zero network overhead, zero latency, and seamless offline functionality.
  - *Alternatives Considered*: Server-side search API (unnecessary latency and failure modes for static catalog data).

- **Decision 2: Substring Highlighting Component (`<HighlightMatch />`)**
  - *Chosen Approach*: Build a lightweight regex/split renderer that wraps matched text segments in `<mark className="bg-cyan-500/30 text-cyan-200 rounded px-0.5 font-semibold">`.
  - *Why*: Guarantees instant visual feedback so users immediately see why a card matched their query.

- **Decision 3: Seamless Integration with Existing Subtabs**
  - *Chosen Approach*: When a search query is typed, the interface offers an unified "Search Results" view displaying all matched flags, security modules, and doc snippets, while also filtering the existing "Flags" and "Docs" tabs. Clearing the search restores the standard tab view.
  - *Why*: Provides the best of both worlds: dedicated search result scanning without losing standard tab browsing workflows.

---

### 4. Technical Architecture & Component Hierarchy

```
┌────────────────────────────────────────────────────────────────────────┐
│                          ScriptInspector.tsx                           │
├────────────────────────────────────────────────────────────────────────┤
│  State:                                                                │
│    - searchQuery: string                                               │
│    - searchScope: 'active' | 'all'                                     │
│    - categoryFilter: 'all' | 'security' | 'core' | 'apps' | 'modifier'  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                 ┌──────────────────┴──────────────────┐
                 ▼                                     ▼
┌─────────────────────────────────┐   ┌──────────────────────────────────┐
│        Search Toolbar           │   │      Search Index Engine         │
│ - Keyword text input with clear │   │ - Indexed Flags & Aliases        │
│ - Scope toggle (Active vs All)  │   │ - Security & Hardening Modules   │
│ - Category filter buttons       │   │ - Key Features & Tech Overview   │
│ - Match count pill              │   │ - Fuzzy/Exact substring matcher  │
└────────────────┬────────────────┘   └────────────────┬─────────────────┘
                 │                                     │
                 └──────────────────┬──────────────────┘
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │             Rendered Matched Results View              │
       │  - <HighlightMatch text={...} query={searchQuery} />   │
       │  - Matched Flag Cards with category & elevation badges │
       │  - Matched Security Controls & Warning Notes           │
       │  - Matched Key Engineering Features                    │
       │  - Action Buttons: Copy Flag, Run Simulator, Jump Code │
       └────────────────────────────────────────────────────────┘
```

#### Data Model for Search Index Item
```typescript
interface SearchIndexEntry {
  type: 'flag' | 'security' | 'feature' | 'overview';
  scriptId: string;
  scriptName: string;
  title: string;
  description: string;
  category?: string;
  flagSyntax?: string;
  warningNote?: string;
  associatedSoftware?: string[];
  requiresElevation?: boolean;
}
```

---

### 5. Verification Plan

1. **Active Script Flag Search**:
   - Type `--harden` -> Verify `--harden` and `--harden-advanced` appear with matched keywords highlighted.
   - Type `cve` -> Verify OpenSSH CVE-2024-6387 mitigation and security hardening features appear.
2. **Catalog-Wide Scope Toggle**:
   - Toggle to "All Catalog Scripts".
   - Type `restic` -> Verify `Restic-Cloud-Backup.sh` flags and modules appear.
   - Type `registry` -> Verify `Windows-Deployment-Tool.ps1` modules appear.
3. **Interactive Actions**:
   - Click "Copy Flag" -> Verify flag string copied to clipboard with visual confirmation.
   - Click "Run in Simulator" -> Verify Simulator tab opens with the selected script and command.
4. **Code Quality & Build Verification**:
   - Run `compile_applet` to ensure error-free TypeScript build.
   - Run `lint_applet` to ensure zero ESLint issues.
