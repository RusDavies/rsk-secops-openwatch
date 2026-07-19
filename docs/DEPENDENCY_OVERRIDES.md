# Dependency Overrides Register

Keep this file small and boring. Overrides are debt, not interior decorating.

## Active overrides

| Package | Current override | Why it exists | Review cadence | Removal criteria |
| --- | --- | --- | --- | --- |
| `postcss` | `8.5.10` | Pin patched PostCSS while the Next dependency tree catches up. | Review monthly and whenever `next` is upgraded. | Remove when `npm ls postcss` shows all production paths resolve to a non-vulnerable upstream-supported version without the override and `npm audit --audit-level=moderate` stays clean. |

## Review procedure

1. Run `npm audit --audit-level=moderate`.
2. Run `npm ls postcss`.
3. Test removing the override on a throwaway branch.
4. Run `npm ci`, `npm run check`, and `npm run build`.
5. If clean, remove the override and this register row in the same commit.
