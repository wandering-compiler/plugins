### A usage period is an ISO 8601 window, in one spelling (`usage`) (read first)

- `ReportUsage` and `GetMyUsageMeter` take `period` only as an ISO 8601
  window: a year `2026`, a month `2026-06`, an ISO week `2026-W23` (Monday
  to Sunday), a day `2026-06-15`, or N days from a day `2026-06-03/P7D`
  (1 to 366). It is stored canonical (`2026-w23` → `2026-W23`,
  `P007D` → `P7D`), so every spelling of one window counts on one meter.
- **Any other spelling is now refused** with `InvalidArgument` naming the
  accepted shapes. Before, `2026/06`, `2026-6` and `June 2026` were each a
  meter of their own. A caller that sent one of them must send the ISO form.
  Meters written earlier under another spelling are left as they were.
