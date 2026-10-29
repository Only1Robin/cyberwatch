# CyberWatch

A platform that tracks cybersecurity news from around the world and uses AI
agents to help defenders understand incidents and prepare for them.

> Work in progress. Built step by step as a portfolio project.

## What it does

| Component | Status | Purpose |
|-----------|--------|---------|
| News collector | Done | Pulls security news and the CISA Known Exploited Vulnerabilities catalog every 3 hours |
| Software attribution agent | Planned | Estimates which software was involved in an incident, with a confidence score |
| Website dashboard | Planned | Public feed, filters and world view |
| Advisor agent | Planned | Explains attack chains from public reports and builds preparedness and authorized-testing checklists |

## How it works

```
GitHub Actions (every 3h)
        |
        v
collector/collect.py  -->  data/news.json, data/kev.json
        |
        v
Website (hosted on Vercel) reads the JSON files
```

The collector reads public RSS feeds and the CISA KEV catalog. When a news
story mentions a CVE that CISA lists, the vendor and product are attached as a
"software hint".

## Run the collector yourself

```bash
pip install -r requirements.txt
python collector/collect.py
```

Output is written to the `data/` folder.

## Sources

BleepingComputer, The Hacker News, Krebs on Security, CISA advisories,
SecurityWeek, and the CISA KEV catalog. Only titles, short snippets and links
are stored; every story links back to its original publisher.

## Ethics

This project is for defensive security and education. Any testing it
recommends must only be done with written permission from the system owner.
