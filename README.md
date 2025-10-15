# Cyber Automation Portfolio

This repository contains a demo static site (docs/index.html) and a small Python automation that generates `docs/alerts.json`. GitHub Actions runs the script and commits the generated file. GitHub Pages serves the site and the alerts.json file which the page reads.

## How to trigger
- Manually: Actions → generate-alerts → Run workflow (workflow_dispatch)
- Automatically: on push or hourly (cron) as configured.

