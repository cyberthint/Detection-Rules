rule Project1_RAT { 
    meta: 
        description = "Project1 RAT - Tespit kuralı" 
        author = "Analyst" 
        date = "2026-02-27" 
        hash = "07131e3fcb9e65c1e4d2e756efdb9f263fd90080d3ff83fbcca1f31a4890ebdb" 
    strings: 
        $pdb = "C:\\Users\\hibby\\Desktop\\Project1" nocase 
        $cmd1 = "/upload-sysinfo" ascii nocase 
        $cmd2 = "/upload-screen" ascii nocase 
        $cmd3 = "/upload-keylog" ascii nocase 
        $cmd4 = "/upload-webcam" ascii nocase 
        $cmd5 = "/upload-audio" ascii nocase 
        $cmd6 = "/upload-tokens" ascii nocase 
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" 
nocase 
        $reg2 = "Software\\Classes\\ms-settings\\Shell\\Open\\command" 
nocase 
        $uac = "fodhelper.exe" nocase 
        $token_regex = /[a-zA-Z0-9_-]{23,28}\.[a-zA-Z0-9_-]{6}\.[a-zAZ0-9_-]{25,110}/ 
        $api = "api.ipify.org" ascii nocase 
    condition: 
        (any of ($cmd*) or $pdb or $reg1 or $reg2 or $uac) or  
        ($token_regex and $api) 
}