rule Sim_Loader_Family
{
    meta:
        description = "Windows executable with loader marker / C2 indicators"
        severity = "high"
        stage = "initial access"
    strings:
        $marker = "EVIL_LOADER_v1"
        $c2     = "c2.evil-example.test" nocase
        $beacon = "beacon" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Sim_PS_Downloader
{
    meta:
        description = "PowerShell download-and-execute"
        severity = "high"
        stage = "execution"
    strings:
        $a = "DownloadString" nocase
        $b = "Invoke-Expression" nocase
        $c = "Net.WebClient" nocase
    condition:
        2 of them
}

rule Sim_Persistence
{
    meta:
        description = "Scheduled task + Run key persistence"
        severity = "high"
        stage = "persistence"
    strings:
        $a = "schtasks /create" nocase
        $b = "CurrentVersion\\Run" nocase
    condition:
        $a and $b
}

rule Sim_Ransom_Note
{
    meta:
        description = "Ransom note text"
        severity = "critical"
        stage = "impact"
    strings:
        $a = "Your files have been encrypted" nocase
        $b = "bitcoin" nocase
        $c = "decrypt" nocase
    condition:
        2 of them and filesize < 5KB
}
