# Client Fix Page

A static web page that tells an admin which script to run so a Windows client is healthy again for patching, Intune, Entra ID and Defender.

## How it works

1. Run `scripts/Get-ClientHealth.ps1` on the affected client. It is read-only and writes a JSON report.
2. Open the page and load the report (upload, drop or paste).
3. The page matches each finding ID against `data/catalog.json` and shows the recommended script, a download link and the command to run.

The report is processed in the browser only. Nothing is uploaded. The page never runs a fix itself.

## Run the diagnostic

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Get-ClientHealth.ps1 -Anonymize -CopyToClipboard
```

Run it elevated for complete results. Useful switches:

| Switch | Effect |
| --- | --- |
| `-Anonymize` | Replaces the computer name with a hash and leaves out user name and tenant ID |
| `-CopyToClipboard` | Copies the JSON so it can be pasted into the page |
| `-OutputPath <file>` | Report path (default: `%TEMP%\ClientHealth-<name>.json`) |
| `-SkipNetwork`, `-SkipUpdateScan`, `-SkipComponentStore` | Skip the slower checks |

## Repository layout

| Path | Content |
| --- | --- |
| `index.html`, `assets/` | The page (no build step, no dependencies) |
| `data/catalog.json` | Maps finding IDs to fix scripts |
| `data/sample-report.json` | Sample report for the "Load sample report" button |
| `scripts/Get-ClientHealth.ps1` | The diagnostic script |
| `.github/workflows/pages.yml` | Deploys the page to GitHub Pages on every push to `main` |

## Add or change a fix

Edit `data/catalog.json`. Each entry needs an `id` that matches a check ID from the diagnostic script.

| Field | Meaning |
| --- | --- |
| `id`, `area`, `title`, `severity` | Finding ID, area, display title, `high` / `medium` / `low` |
| `status` | `available` (safe to recommend), `needs-fix` (script exists but has known issues), `manual` (no script on purpose; `manualSteps` is the guide), `planned` (no script yet) |
| `repo`, `script`, `download` | Repository URL, script path and direct download URL (https only) |
| `command` | Command line shown with a copy button |
| `risk`, `note` | Risk level and a warning shown above the fix |
| `manualSteps` | Steps shown when there is no script |

To cover a new area (for example a Defender fix repository), add the check to `Get-ClientHealth.ps1` and an entry with the same ID to the catalog. No change to the page code is needed.

## Run locally

The page loads `data/catalog.json` with `fetch`, so open it through a web server, not as a file:

```bash
python3 -m http.server 8080
```

## Publish

In the repository settings, set **Pages → Build and deployment → Source** to **GitHub Actions**. The workflow then publishes every push to `main`.
