# Client Fix Page

A static web page that tells an admin which script to run so a Windows client is healthy again for patching, Intune enrollment, Entra ID join, BitLocker, drivers, Company Portal and Defender.

## How it works

1. Run `scripts/Get-ClientHealth.ps1` on the affected client. It is read-only and writes a JSON report.
2. Open the page and load the report (upload, drop or paste).
3. The page matches each finding ID against `data/catalog.json` and shows the recommended script, a download link and the command to run.

Without a report, admins can also type a problem (or pick an area or a common problem) under **Find a fix by problem** and get the matching scripts and step-by-step guides from the catalog.

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
| `-IntuneMode` | Remediation mode (see below); on automatically when run as SYSTEM |

## Run it as an Intune Remediation

Upload `Get-ClientHealth.ps1` as the **detection script only** (Devices > Scripts and remediations > Remediations), run as SYSTEM in 64-bit PowerShell, schedule daily or run it on demand with "Run remediation".

As SYSTEM the script switches to Intune mode by itself (Intune passes no parameters):

- The report goes to `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\ClientHealth-<COMPUTERNAME>.json`. That folder is included in **Collect diagnostics**, so you can get the JSON from the Intune admin center without touching the device.
- The output is one line with the overall state and the finding IDs, shown in the remediation's device status (column "Pre-remediation detection output").
- Exit code 1 when a check failed (device shows "With issues"), otherwise 0.

As SYSTEM the user-only checks (Primary Refresh Token, Entra registration dual state) are reported as `info`.

## Repository layout

| Path | Content |
| --- | --- |
| `index.html`, `assets/` | The page (no build step, no dependencies). Design, fonts and logo follow [letmetrythis.dev](https://letmetrythis.dev/) |
| `data/catalog.json` | Maps finding IDs to fix scripts |
| `data/sample-report.json` | Sample report for the "Load sample report" button |
| `scripts/Get-ClientHealth.ps1` | The diagnostic script |
| `.github/workflows/pages.yml` | Deploys the page to GitHub Pages on every push to `main` |

## Change the page

When you change `assets/style.css`, `assets/site.js` or `assets/app.js`, raise the `?v=` value on their links in `index.html`. Browsers cache these files, and without a new value they show the new page with the old styles.

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
