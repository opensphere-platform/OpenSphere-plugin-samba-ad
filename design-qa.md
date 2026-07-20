# Samba-AD / PostgreSQL layout parity QA

- Date: 2026-07-20
- Reference: `C:\Users\cmars\AppData\Local\Temp\opensphere-addc-postgres-ui\05-postgres-current.png`
- Implementation: `C:\Users\cmars\AppData\Local\Temp\opensphere-addc-postgres-ui\04-addc-edge6.png`
- Browser: user Chrome
- Viewport: 8456 × 2560 CSS pixels
- State: preflight / operator required

## Acceptance comparison

| Area | PostgreSQL reference | Samba-AD result | Result |
| --- | --- | --- | --- |
| Page shell | Breadcrumb, PFS back link, unified product header | Same order and full-width alignment | Pass |
| Header | Logo, capability eyebrow, title, description, 4 metadata columns | Same structure; AD-specific content only | Pass |
| Tabs | 11-tab operational spine | Same order and count; `Directory & Roles` replaces `Databases & Roles` | Pass |
| Lifecycle | Operator preparation → cluster creation → operations | Same 3-step strip and enabled/disabled behavior | Pass |
| Overview | Three equal-width operational panels | Package readiness, Directory health, Operations policy | Pass |
| Footer content | Description and Documentation columns | Same layout with Samba-AD manual links | Pass |
| Typography and spacing | Console Clarity tokens and plugin page tokens | Same shared stylesheet/token classes | Pass |
| Borders and colors | Flat white surfaces, thin neutral borders, blue active line | Same treatment | Pass |
| Logo asset | Product logo without decorative placeholder | `logos.opl.io.kr` Samba asset | Pass |
| Interaction | Operator, Cluster plan, Documentation tabs navigate | Verified in Chrome at `/operator`, `/cluster`, `/documentation` | Pass |

## Iterations

1. The initial Samba-AD screen had no PFS back link, a reduced tab set, a narrow two-card overview, and a different page rhythm.
2. The first shared-runtime build exposed a reload defect (`API_BASE is not defined`); all residual global API references were replaced with the persistent runtime slot and protected by verification assertions.
3. Edge 0.1.1-edge.6 now uses the PostgreSQL page spine and full-width overview while retaining only domain-specific AD terminology and status data.

## Runtime evidence

- UI package: `0.1.1-edge.6`
- Source revision: `056dfd977f2d7e326d83a08a68e43deaefbf3106`
- Image digest: `sha256:c04f8728f31159317ee311d8f48715471a55da8bd92be77d5d4f5b0e4773e4af`
- Controller: manifest Verified, entry digest Verified, signature Verified, workload Ready
- Automated verification: 17 passed, 0 failed

final result: passed
