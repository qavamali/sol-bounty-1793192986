# Vaultline Security Audit Grants Intake & Pre-Audit Engine for Colosseum Projects

[![Solana](https://img.shields.io/badge/Solana-Anchor%20v0.30+-14F195?logo=solana&logoColor=white)](https://solana.com)
[![Vaultline](https://img.shields.io/badge/Vaultline-Audit%20Grants-blueviolet)](https://vaultline.xyz)
[![Colosseum](https://img.shields.io/badge/Colosseum-Accelerator%20%26%20Hackathon-orange)](https://colosseum.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An enterprise-grade Pre-Audit Security Assessment and Grant Application Platform engineered specifically for Solana projects emerging from **Colosseum** competitions (Radar, Renaissance, Breakout, etc.) applying for **Vaultline Security Audit Grants (Up to 4,000 USDC each)**.

---

## 1. Executive Summary

Vaultline offers up to **4,000 USDC** in security audit grant subsidies per qualifying Colosseum project. Because formal security audits require significant technical intake, scoping, and threat modeling, projects that apply with unvetted codebases, missing unit tests, or unverified Anchor constraints often experience prolonged evaluation times.

This platform automates:
1. **Colosseum Provenance & Eligibility Verification**: Validates project repository metadata, commit histories, track participation, and Colosseum directory registration.
2. **Automated Static Security Analysis (Anchor / Native Rust)**: Analyzes Anchor code for top Solana vulnerability patterns (missing signer checks, arbitrary CPIs, unvalidated PDA bump seeds, re-initialization exploits, duplicate mutable account references, and close account rent recovery flaws).
3. **Audit Scoping & SLOC Complexity Scoring**: Scans instruction handlers, state structs, and external program calls to compute an algorithmic complexity coefficient and exact audit budget.
4. **Grant Dossier Generator**: Assembles a standardized, cryptographically signed Vaultline Audit Grant Application containing threat vectors, automated scan findings, architecture maps, and requested funding allocations (up to 4,000 USDC).

---

## 2. Architecture & Vulnerability Detection Matrix

```
                          COLOSSEUM PROJECT APPLICANT
                                       │
                      (GitHub Repo / Anchor Workspace)
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       VAULTLINE SECURITY PIPELINE                           │
│                                                                             │
│  [1] Intake & Provenance       [2] Static Security Scanner                  │
│      ├─ Colosseum Track ID         ├─ Signer & Ownership Verification       │
│      ├─ Hackathon Branch/Tag       ├─ PDA Bump Constraint Auditing          │
│      └─ Commit Timestamp Engine    ├─ Reentrancy & Close Account Rent       │
│                                    └─ Unchecked Arithmetic & Account Dups   │
│                                                                             │
│  [3] Complexity & Scope Engine [4] Grant Dossier & Ledger Formatter         │
│      ├─ SLOC & Instruction Count   ├─ Vulnerability Severity Grading        │
│      ├─ External CPI Weighting     ├─ Grant Subsidy Allocator (Max 4K USDC) │
│      └─ Test Coverage Multiplier   └─ Signed Submission Hash (Ed25519)      │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
             VERIFIED AUDIT GRANT PACKAGE -> SUBMITTED TO VAULTLINE
```

### Static Analysis Security Vectors Handled

| Vector Code | Vulnerability Category | Description & Check |
|---|---|---|
| `VL-SEC-01` | **Missing Signer Verification** | Verifies that write operations and administrative operations explicitly enforce `Signer<'info>` or `#[account(signer)]`. |
| `VL-SEC-02` | **Arbitrary CPI Injection** | Flags unpinned `program_id` targets in cross-program invocations (`cpi_context`). |
| `VL-SEC-03` | **Insecure Account Closure** | Validates that target recipient accounts do not point back to the closing program, preventing resurrection/rent drainage attacks. |
| `VL-SEC-04` | **Canonical Bump Invalidation** | Checks that `seeds = [...]` include explicit `bump = ctx.bumps.name` or `bump` storage instead of dynamic search via `find_program_address`. |
| `VL-SEC-05` | **Duplicate Mutable Accounts** | Detects instances where mutable accounts can be aliased to the same public key without validation constraints. |
| `VL-SEC-06` | **Type Cosplay / Owner Check** | Ensures native `AccountInfo` wrappers validate `owner == expected_program_id`. |
| `VL-SEC-07` | **Unchecked Arithmetic** | Identifies unchecked integer operations in financial and token-minting calculations without checked/saturating helpers. |

---

## 3. Directory Structure

```
vaultline-colosseum-grants/
├── src/
│   ├── index.ts               # Express API and CLI entry point
│   ├── scanner/
│   │   ├── analyzer.ts        # Anchor Rust AST regex & static security rules
│   │   └── rules.ts           # Security rule definitions and severity mappings
│   ├── colosseum/
│   │   └── verifier.ts        # Colosseum repo, commit, and eligibility checker
│   ├── scoping/
│   │   └── calculator.ts      # SLOC, complexity, and grant tier allocator (up to $4,000)
│   └── report/
│       └── dossier.ts         # Markdown & JSON dossier generation engine
├── package.json
└── tsconfig.json
```

---

## 4. Setup Instructions

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **npm** or **yarn** / **pnpm**
- **Rust / Anchor CLI** (optional, for local project compilation checks)

### Installation
```bash
# Clone the workspace
git clone https://github.com/vaultline-security/colosseum-audit-grants.git
cd colosseum-audit-grants

# Install dependencies
npm install

# Build TypeScript
npm run build
```

### Running the CLI Scanner
To scan a Colosseum project Anchor workspace and generate an audit grant proposal:

```bash
# Run against a local Anchor project
npm start -- scan \
  --path /path/to/colosseum/solana-project \
  --project "Solsurance DeFi" \
  --track "DeFi & Capital Markets" \
  --colosseum-id "COL-RADAR-2024-8841" \
  --output ./grant-application.json
```

### Running the API Server
Vaultline provides a REST API backend for automated dashboard submissions:

```bash
# Start the HTTP server on port 4000
npm start -- serve --port 4000
```

#### API Endpoints
- `POST /api/v1/grants/scan`: Upload or specify a git repository for automated security scanning.
- `POST /api/v1/grants/submit`: Submit a fully packaged grant application to Vaultline.
- `GET /api/v1/grants/:id`: Fetch application status, score breakdown, and grant subsidy allocation.

---

## 5. Grant Allocation Matrix (Up to $4,000 USDC)

| Score Threshold | Complexity Level | Recommended Grant Subsidy | Audit Readiness Level |
|---|---|---|---|
| 85 - 100 | High / Protocol Grade | **$4,000 USDC** (Full Grant) | Excellent: Ready for immediate execution |
| 70 - 84 | Medium - High | **$3,000 USDC** | High: Minor pre-audit remediation required |
| 50 - 69 | Moderate | **$2,000 USDC** | Moderate: Moderate remediation required |
| < 50 | Low / Needs Polish | Re-scan required prior to grant issuance | Unauditable: Critical baseline issues detected |