import hashlib, os

def rd(p): return open(p, encoding='utf-8').read()
def wr(p, s): open(p, 'w', encoding='utf-8', newline='\n').write(s)
def rep(s, a, b, label):
    assert s.count(a) == 1, 'not found: ' + label
    return s.replace(a, b)

s = rd('setup.sh')
if '.yara-live-hunt' not in s:
    s = rep(s, 'rm -rf "$LAB"\n', '''if [ -e "$LAB" ] && [ ! -f "$LAB/.yara-live-hunt" ]; then
  echo "Refusing to delete $LAB: it was not created by YARA Live Hunt. Rename or move it, then run again."
  exit 1
fi
rm -rf "$LAB"
''', 'rm -rf LAB')
    s = rep(s, 'cp "$SRC/attack_sim.sh" "$LAB/"\n', 'touch "$LAB/.yara-live-hunt"\ncp "$SRC/attack_sim.sh" "$LAB/"\n', 'cp attack')
    wr('setup.sh', s)

c = rd('agent/connect.sh')
if 'yh_clean' not in c:
    c = rep(c, 'bash "$YH/src/setup.sh"\n', 'bash "$YH/src/setup.sh" || { echo "Setup stopped. Nothing was changed."; return 1; }\n', 'setup call')
    c = rep(c, 'echo "Connected.', '''yh_clean() {
  printf 'Stop the helper and delete ~/yara-lab, ~/.yara-hunt and ~/.yh-connect.sh? [y/N] '; read -r __a
  case "$__a" in y|Y) ;; *) echo "Cancelled."; return 0;; esac
  yh_off
  if [ -f "$HOME/yara-lab/.yara-live-hunt" ]; then rm -rf "$HOME/yara-lab"; else echo "Skipped ~/yara-lab (not created by YARA Live Hunt)."; fi
  rm -rf "$HOME/.yara-hunt" "$HOME/.yh-connect.sh"; echo "Removed."
}
echo "Connected.''', 'connected echo')
    c = rep(c, '(undo with: yh_off)', '(disconnect: yh_off, remove everything: yh_clean)', 'undo text')
    c = rep(c, 'Lab kept at ~/yara-lab (rm -rf it to remove).', 'Lab kept at ~/yara-lab (run yh_clean to remove everything).', 'off msg')
    wr('agent/connect.sh', c)

h = rd('index.html')
if 'yh_clean' not in h:
    h = rep(h, '<li>Run <code>yh_off</code> when finished</li>', '<li>Run <code>yh_off</code> when finished. Nothing is deleted automatically: to remove everything, run <code>yh_clean</code></li>', 'checklist')
    h = rep(h, 'Run <code>yh_off</code>, close this tab, and delete the folders <code>~/yara-lab</code> and <code>~/.yara-hunt</code>. That removes everything the connector created.', 'Run <code>yh_clean</code>. It stops the helper and, after you confirm, deletes <code>~/yara-lab</code>, <code>~/.yara-hunt</code> and <code>~/.yh-connect.sh</code>. Then close this tab.', 'wrong card')
    h = rep(h, 'Neither sees what happens between your browser and your own terminal.</p>', 'Neither sees what happens between your browser and your own terminal.</p><p class="mu">This is a practice lab, not a sandbox: the operating system does not isolate it. For real isolation, use a throwaway virtual machine.</p>', 'sandbox note')
    wr('index.html', h)
        
r = rd('README.md')
if 'yh_clean' not in r:
    wr('README.md', r.rstrip('\n') + '\n\n## Cleanup\nNothing is deleted automatically. `yh_off` disconnects. `yh_clean` stops the helper and, after you confirm, deletes `~/yara-lab`, `~/.yara-hunt` and `~/.yh-connect.sh`. `setup.sh` refuses to delete a `~/yara-lab` that this tool did not create.\n')

files = ['agent/connect.sh', 'agent/yara-hunt-agent.py', 'setup.sh', 'attack_sim.sh', 'rules/rules.yar']
lines = []
for f in files:
    d = open(f, 'rb').read().replace(b'\r\n', b'\n')
    lines.append(hashlib.sha256(d).hexdigest() + '  ' + f)
wr('SHA256SUMS', '\n'.join(lines) + '\n')
print('done')