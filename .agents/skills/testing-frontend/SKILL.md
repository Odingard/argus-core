# Testing ARGUS React Frontend

## Dev Server
```bash
cd argus-frontend && npm run dev
# Typically starts on port 5173; if occupied, Vite auto-picks 5174
```

## Login Bypass (no backend)
The frontend requires an `argus_token` in localStorage. To bypass login when the backend isn't running:
```js
// In browser console (must be on localhost:5173 origin first)
localStorage.setItem("argus_token", "test");
window.location.href = "/";
```
Or via Playwright CDP:
```python
from playwright.sync_api import sync_playwright
p = sync_playwright().start()
browser = p.chromium.connect_over_cdp("http://localhost:29229")
page = browser.contexts[0].pages[0]
page.goto("http://localhost:5173/login")
page.wait_for_load_state("networkidle")
page.evaluate('localStorage.setItem("argus_token", "test")')
page.goto("http://localhost:5173/")
page.wait_for_load_state("networkidle")
p.stop()
```

## Key Pages to Test
| Route | Page | What to verify |
|---|---|---|
| /login | Login | Dark theme, error messages for empty/invalid token |
| / | Dashboard | Stats cards, trend chart, severity pie, 12 agent grid, alerts |
| /scan/live | Live Scan | 12 agent cards, Launch button, findings accumulation |
| /findings | All Findings | 8 mock findings, expandable rows, severity badges |
| /platform/settings | Settings | 7 sub-tabs (API Keys, Scan Profiles, etc.) |

## Key Bug Fixes to Regression-Test
1. **Login error display**: Submit empty or invalid token — error should show in red, page should NOT reload
2. **Live scan findings**: Start scan, watch findings — counts must only increase, never decrease
3. **Live scan reset**: Complete scan, start new scan — all agents must reset to 0 findings/0% progress
4. **Findings expand/collapse**: Click row to expand, click again to collapse, click different row — only one expanded at a time

## Common Issues
- **Tailwind config**: Must be `tailwind.config.cjs` (CommonJS), not `.js` — project uses `"type": "module"` in package.json
- **shadcn/ui components**: Must use `cssVariables: true` in `components.json` for Tailwind v3 compatibility
- **Port conflicts**: If port 5173 is busy, Vite picks 5174. Kill stale processes: `lsof -ti:5173 | xargs -r kill -9`
- **Browser console tool**: May not detect Chrome as foreground — use Playwright CDP as fallback for localStorage operations

## Build Check
```bash
cd argus-frontend && npm run build
# Should produce dist/ with ~880KB JS bundle, no errors
```
