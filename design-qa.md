# Samba-AD / PostgreSQL layout parity QA

- Date: 2026-07-20
- Source visual truth: `C:\Users\cmars\AppData\Local\Temp\codex-clipboard-c11c6ec5-8587-4df1-a4c8-7f910f110e2e.png`
- Runtime reference capture: `audit-evidence/2026-07-20-addc-postgres-parity/postgres-edge11-overview.jpg`
- Implementation capture: `audit-evidence/2026-07-20-addc-postgres-parity/addc-edge7-current.jpg`
- Full-view comparison: `audit-evidence/2026-07-20-addc-postgres-parity/postgres-addc-side-by-side.jpg`
- Focused header/tab comparison: `audit-evidence/2026-07-20-addc-postgres-parity/postgres-addc-header-tabs-focused.jpg`
- Interaction capture: `audit-evidence/2026-07-20-addc-postgres-parity/02-addc-operator-selected.jpg`
- Browser: user Chrome
- Viewport: 1728 × 859 CSS pixels
- State: operator required / directory not created

## Findings

No actionable P0, P1, or P2 differences remain between the PostgreSQL reference and the ADDC implementation.

| Fidelity surface | Evidence and result |
| --- | --- |
| Information architecture | Both pages use breadcrumb → PFS back link → unified product header → 11-tab spine → 3-stage strip → 3-column Overview. Pass. |
| Fonts and typography | Both surfaces inherit the same Console/Clarity font stack, weights, line heights, muted labels, and heading hierarchy. Product names and domain-specific copy are the only intentional differences. Pass. |
| Spacing and layout rhythm | Header bounds, metadata columns, tab baseline, stage widths, panel gaps, borders, and above-the-fold density align in the focused comparison. Pass. |
| Colors and visual tokens | White surfaces, neutral borders, blue active indicators, amber lifecycle badge, muted disabled tabs, and semantic green status text use the same tokens. Pass. |
| Image quality and asset fidelity | PostgreSQL and Samba logos are the product assets supplied through the approved logo source; neither uses a decorative placeholder or handcrafted graphic. Their intrinsic aspect ratios are intentionally preserved. Pass. |
| Copy and content | The same labels are retained where the task is equivalent. `Directory & Roles` and `Directory health` intentionally replace PostgreSQL-specific database terminology. Pass. |
| Accessibility | The ADDC tablist exposes 11 tabs, one selected tab, disabled-state explanations, roving focus, and ArrowRight navigation from Overview to Operator. Pass for the tested keyboard path. |

## Full-view comparison evidence

The combined image shows PostgreSQL on the left and ADDC on the right at the same viewport and lifecycle state. Major-region proportions and visible density match. The three Overview panels are equal-width in both pages.

## Focused region comparison evidence

The header/tab/stage crop was required because the full page is dense. It confirms identical header composition, four metadata columns, 11-tab order, active-line treatment, and three equal lifecycle stages.

## Comparison history

1. **Initial reference (edge.6):** ADDC had eight tabs, a shortened lifecycle strip, two narrow cards, and an unrelated `다음 작업` block. This was a P1 structural mismatch.
2. **Fix:** ADDC adopted the PostgreSQL page contract: 11 tabs, full-width product header, three lifecycle stages, and three equal Overview panels. Domain copy was mapped without changing the common shell.
3. **Post-fix evidence (edge.7):** Chrome capture at `/p/foundation/addc` matches PostgreSQL’s structure. ArrowRight moves `Overview` to selected `Operator` and the route changes to `/p/foundation/addc/operator`.

## Runtime evidence

- UI package: `0.1.1-edge.7`
- Source revision: `f36f3f2148cc601a7641e35b6b9d33e5d9ef8e87`
- Image digest: `sha256:21fa2d8c4ab3c83bcf10cf0d310f247523d48971af5fa034c443c2807dca77fa`
- Registry state: `Enabled`, `Activated`, `Ready`
- Verification: manifest Verified, entry digest Verified, signature Verified, permissions Approved
- Runtime: `opensphere-console/samba-ad`, 2/2 replicas Ready
- Browser console: 0 warnings/errors in the inspected ADDC run
- Tabs: 11 rendered; Overview → ArrowRight → Operator verified

## Follow-up polish

- No P3 visual change is required for the requested PostgreSQL parity. Product-specific operational values will naturally differ after AD DC creation.

final result: passed
