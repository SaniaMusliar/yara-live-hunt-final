#!/bin/bash
# Builds a clean fake file server in ~/yara-lab and copies the rules + attack script in.
SRC="$(cd "$(dirname "$0")" && pwd)"
LAB=~/yara-lab
rm -rf "$LAB"
mkdir -p "$LAB"/fileserver/{finance,hr,mail_attachments,shared,users/john/Downloads,users/john/AppData} "$LAB/rules"
cp "$SRC/attack_sim.sh" "$LAB/"
cp "$SRC/rules/rules.yar" "$LAB/rules/"
cd "$LAB/fileserver"
for i in $(seq 1 100); do echo "Quarterly report $i - revenue and notes" > finance/report_$i.txt; done
for i in $(seq 1 50);  do echo "Employee record $i - leave balance" > hr/emp_$i.txt; done
cat > shared/admin_backup.ps1 << 'EOT'
# Legit nightly backup script (one suspicious word on purpose: false-positive test)
$cfg = Get-Content C:\backup\config.txt
Invoke-Expression $cfg
EOT
echo "Clean file server ready: $(find "$LAB/fileserver" -type f | wc -l) files"
