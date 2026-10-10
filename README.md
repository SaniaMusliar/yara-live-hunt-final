# YARA Live Hunt

**Live site:** https://yara-live-hunt-file.vercel.app

Simulate a ransomware attack with **harmless text files**, hunt it with real YARA rules, and watch your own
Linux / WSL / Kali terminal mirrored live in the browser. Hash search finds exact copies; YARA finds the variants.

- **Guided demo**: runs entirely in the browser, no install.
- **Connect terminal**: paste one command into your shell; files you create or delete in `~/yara-lab` appear on the page.

## How the bridge works
The page generates a one-time token and a copy-paste command. The command downloads `agent/connect.sh`, builds
`~/yara-lab`, starts `agent/yara-hunt-agent.py` on **127.0.0.1 only**, and hooks your current shell (bash or zsh).
The page then polls your local agent. Nothing goes through a third-party server.
The agent requires the token and the exact site origin, checks the Host header, reads only `~/yara-lab`, and runs one
fixed command (`yara -r -s -m rules/rules.yar fileserver`). It never executes anything the website sends.
Undo with `yh_off`. Works in Chrome, Edge, Firefox; Safari blocks https-to-localhost.

## Requirements
Linux / WSL / Kali, `python3`, `curl`, `yara` (`sudo apt install yara -y`).

## Layout
`index.html` site · `agent/` local bridge · `rules/rules.yar` · `setup.sh` + `attack_sim.sh` lab · `LICENSE`

## License, use and notices
Educational use only. Run it only on machines you own or may test. No real malware is included or created.
YARA (VirusTotal, BSD-3-Clause) is installed separately. Inter font: SIL OFL 1.1 via Google Fonts.
Not affiliated with VirusTotal, Google, OffSec or Microsoft; all trademarks belong to their owners.
Not legal advice.

## Honest limitations
Teaching tool, not antivirus. YARA only detects; a match is a lead, not a verdict, and no match is not proof of safety. Demo rules are simple and must not be used to judge real files. The connector runs a script on your machine and has had no third-party audit: read it first. Do not type secrets in the connected shell; commands typed inside `~/yara-lab` are logged and shown on the Connect page. Hosting and Google Fonts see normal request data such as IP addresses. Provided as is, without warranty.
