/*
    Yara Rule: KarstoRat Detection
    Description: Detects KarstoRat (aka Project1 RAT) based on unique strings, PDB path, and command endpoints
    Author: Cyberthint Threat Intelligence Team
    Date: 2026-03-03
    Reference: https://cyberthint.io/karstorat-rat-case-study
*/

rule KarstoRat {
    meta:
        description = "KarstoRat Remote Access Trojan Detection Rule"
        author = "Cyberthint"
        date = "2026-03-03"
        hash_sha256 = "07131e3fcb9e65c1e4d2e756efdb9f263fd90080d3ff83fbcca1f31a4890ebdb"
        mitre_attack = "T1056.001, T1113, T1123, T1125, T1547.001, T1548.002"
        severity = "high"
    strings:
        // PDB Path from developer machine
        $pdb = "C:\\Users\\hibby\\Desktop\\Project1\\Project1\\x64\\Release\\Project1.pdb" nocase
        
        // C2 Endpoints
        $cmd1 = "/upload-sysinfo" ascii nocase
        $cmd2 = "/upload-screen" ascii nocase
        $cmd3 = "/upload-keylog" ascii nocase
        $cmd4 = "/upload-webcam" ascii nocase
        $cmd5 = "/upload-audio" ascii nocase
        $cmd6 = "/upload-tokens" ascii nocase
        $cmd7 = "/client-download" ascii nocase
        $cmd8 = "/notify?event=heartbeat" ascii nocase
        
        // Registry Persistence
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityService" nocase
        $reg2 = "Software\\Classes\\ms-settings\\Shell\\Open\\command" nocase
        $reg3 = "DelegateExecute" nocase
        
        // UAC Bypass
        $uac1 = "fodhelper.exe" nocase
        $uac2 = "ms-settings" nocase
        
        // External IP Check
        $api1 = "api.ipify.org" ascii nocase
        
        // Discord Token Regex Pattern
        $token_regex = /[a-zA-Z0-9_-]{23,28}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{25,110}/
        
        // Self-destruct
        $selfdestruct1 = "SELF_DESTRUCT" ascii nocase
        $selfdestruct2 = "cleanup.bat" ascii nocase
        
        // Command strings
        $cmd_screenshot = "SCREENSHOT" ascii nocase
        $cmd_keylog_on = "KEYLOG_ON" ascii nocase
        $cmd_shell_start = "SHELL_START" ascii nocase
        
    condition:
        // PDB path is the strongest indicator
        $pdb or
        
        // Any two C2 endpoints
        (2 of ($cmd*)) or
        
        // Registry persistence indicators
        ($reg1 or $reg2) or
        
        // UAC bypass indicators
        ($uac1 and $uac2) or
        
        // Discord token regex + external IP check
        ($token_regex and $api1) or
        
        // Command strings
        (any of ($cmd_*) and any of ($selfdestruct*))
}