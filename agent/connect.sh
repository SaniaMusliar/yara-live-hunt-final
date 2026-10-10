# YARA Live Hunt connector (MIT). Works in bash and zsh (Kali default). Must be SOURCED:
#   source connect.sh --token TOKEN --origin ORIGIN --base URL [--port 8765]
# It (1) downloads 4 small files to ~/.yara-hunt, (2) builds the harmless lab in ~/yara-lab,
# (3) starts the local agent on 127.0.0.1 only, (4) hooks THIS shell so typed commands show in the web UI.
# Undo everything with:  yh_off
__t=""; __o=""; __b=""; __p=8765
while [ $# -gt 0 ]; do case "$1" in --token) __t=$2; shift 2;; --origin) __o=$2; shift 2;; --base) __b=$2; shift 2;; --port) __p=$2; shift 2;; *) shift;; esac; done
if [ -z "$__t" ] || [ -z "$__o" ] || [ -z "$__b" ]; then echo "Missing --token/--origin/--base. Copy the command from the Connect page."; return 1 2>/dev/null; fi
case "$(uname -s)" in Linux) ;; *) echo "This connector needs Linux, WSL or Kali (found $(uname -s)). Use the Guided demo on the website instead."; return 1;; esac
for __c in python3 curl; do command -v "$__c" >/dev/null || { echo "Missing tool: $__c. Install: sudo apt update && sudo apt install -y python3 curl yara"; return 1; }; done
command -v yara >/dev/null || echo "NOTE: yara not found. The lab will build, but scans need it:  sudo apt install -y yara"
YH="$HOME/.yara-hunt"; export YLAB="$HOME/yara-lab"; mkdir -p "$YH/src/rules"
for f in setup.sh attack_sim.sh; do curl -fsSL "$__b/$f" -o "$YH/src/$f" || { echo "download failed: $f"; return 1; }; done
curl -fsSL "$__b/rules/rules.yar" -o "$YH/src/rules/rules.yar" && curl -fsSL "$__b/agent/yara-hunt-agent.py" -o "$YH/agent.py" || { echo "download failed"; return 1; }
for f in "$YH/src/setup.sh" "$YH/src/attack_sim.sh" "$YH/agent.py"; do head -c 2 "$f" | grep -q '^#' || { echo "Unexpected download (not a script): $f. Aborting."; return 1; }; done
bash "$YH/src/setup.sh" || { echo "Setup stopped. Nothing was changed."; return 1; }
pkill -f "$YH/agent.py" 2>/dev/null
nohup python3 "$YH/agent.py" --token "$__t" --origin "$__o" --port "$__p" >"$YH/agent.log" 2>&1 &
disown 2>/dev/null
__ylog() { case "$PWD/" in "$YLAB"/*) ;; *) return;; esac; [ -d "$YLAB" ] && [ -n "$1" ] && printf '%s\t%s\n' "$(date +%s.%N)" "$1" >> "$YLAB/.feed.log"; }
if [ -n "$ZSH_VERSION" ]; then
  preexec_functions=(${preexec_functions:#__ylog} __ylog)
else
  __ylb() { local n c; n=$(HISTTIMEFORMAT= history 1 | awk '{print $1}'); [ "$n" = "$__yn" ] && return; __yn=$n
    c=$(HISTTIMEFORMAT= history 1 | sed 's/^ *[0-9]* *//'); __ylog "$c"; }
  case "$PROMPT_COMMAND" in *__ylb*) ;; *) PROMPT_COMMAND="__ylb${PROMPT_COMMAND:+;$PROMPT_COMMAND}";; esac
fi
yh_off() { pkill -f "$YH/agent.py"; if [ -n "$ZSH_VERSION" ]; then preexec_functions=(${preexec_functions:#__ylog}); else PROMPT_COMMAND="${PROMPT_COMMAND//__ylb;/}"; PROMPT_COMMAND="${PROMPT_COMMAND//__ylb/}"; fi; echo "YARA Live Hunt disconnected. Lab kept at ~/yara-lab (run yh_clean to remove everything)."; }
yh_clean() {
  printf 'Stop the helper and delete ~/yara-lab, ~/.yara-hunt and ~/.yh-connect.sh? [y/N] '; read -r __a
  case "$__a" in y|Y) ;; *) echo "Cancelled."; return 0;; esac
  yh_off
  if [ -f "$HOME/yara-lab/.yara-live-hunt" ]; then rm -rf "$HOME/yara-lab"; else echo "Skipped ~/yara-lab (not created by YARA Live Hunt)."; fi
  rm -rf "$HOME/.yara-hunt" "$HOME/.yh-connect.sh"; echo "Removed."
}
echo "Connected. Open the Connect page, then: cd ~/yara-lab   (disconnect: yh_off, remove everything: yh_clean)"
