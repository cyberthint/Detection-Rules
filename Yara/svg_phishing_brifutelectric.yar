rule SVG_Phishing_Brifutelectric_Main {
    meta:
        description = "Detects SVG files containing obfuscated JavaScript with accounting@brifutelectric.com targeting"
        date = "2026-03-12"
        hash_md5 = "e3b5a03fac7092fa61129ab6d97cd20a"
        hash_sha256 = "4d98123fe95b1a4a318b28ee13bccf1dc45b3b3222b636341c569193c1425aed"
        mitre_attack = "T1027, T1566.002, T1071.001, T1102, T1530"
        severity = "CRITICAL"
    
    strings:
        // Email pattern
        $email1 = "accounting@brifutelectric.com" ascii wide
        $email2 = /[a-zA-Z0-9._%+-]+@brifutelectric\.com/ ascii wide
        
        // XOR obfuscation patterns
        $xor1 = "charCodeAt" ascii
        $xor2 = "String.fromCharCode" ascii
        $xor3 = " ^ " ascii
        $xor_key = "6795a9a7242893e6ef978723" ascii
        
        // Base64 encoded payload
        $b64_hp = "QV5XUQ5OT1tdV1NMUFwLGA0UXFEYChJSQlhbHUNYKRUZE2AIHhgFVS0GEhB1ARUYEXtAEkpZWEZSHxVbQBROVlARWRxYVQBTHRUAX0MSQ1Z1FhlYb1sFHQUFClcTV2BbVhxZeQxZShV4RBATG1YMFE5EDEAaHFJRdVcSF1hoQxwVVnofElMBcgVNHmFVEBlTA35ZHkZ3NBAZVHcNWRgFZyIGEhVURxAYFHtOF0pZXApSHRlMWwg=" ascii
        
        // JavaScript functions
        $atob = "atob" ascii
        $eval = "eval" ascii
        $window_location = "window.location.href" ascii
        
        // SVG indicators
        $script_tag = "<script" ascii nocase
        $cdata = "<![CDATA[" ascii
        
        // XOR variables
        $xp_var = "xp = " ascii
        $qc_var = "qc = " ascii
        $fb_var = "fb = " ascii
        $tb_var = "tb = " ascii
        
        // Domain patterns
        $domain1 = "brifutelectric.com" ascii
        $domain2 = "poocheasta.biz.pl" ascii
        
    condition:
        (uint16(0) == 0x3C3F or uint32(0) == 0x76733C or $script_tag) and
        (
            $email1 or $email2 or
            ($atob and ($xor1 or $xor2)) or
            $b64_hp or
            ($tb_var and $domain1)
        )
}

rule SVG_Phishing_Brifutelectric_XOR_Key {
    meta:
        description = "Detects the XOR key used in the SVG phishing campaign"
        date = "2026-03-12"
        severity = "HIGH"
    
    strings:
        $xp = "6795a9a72428" ascii
        $qc = "93e6ef978723" ascii
        $fb = "6795a9a7242893e6ef978723" ascii
    
    condition:
        ($xp and $qc) or $fb
}

rule SVG_Phishing_Brifutelectric_Chunked_Base64 {
    meta:
        description = "Detects the chunked Base64 pattern used in the SVG phishing campaign"
        date = "2026-03-12"
        severity = "HIGH"
    
    strings:
        $chunk1 = "aH" ascii
        $chunk2 = "R0" ascii
        $chunk3 = "cH" ascii
        $chunk4 = "M6" ascii
        $chunk5 = "Ly" ascii
        $chunk6 = "9q" ascii
        $chunk7 = "cy" ascii
        $chunk8 = "5w" ascii
        $chunk9 = "b2" ascii
        $chunk10 = "9j" ascii
        $chunk11 = "aG" ascii
        $chunk12 = "Vh" ascii
        $chunk13 = "c3" ascii
        $chunk14 = "Rh" ascii
        $chunk15 = "Lm" ascii
        $chunk16 = "Jp" ascii
        $chunk17 = "ei" ascii
        $chunk18 = "bC" ascii
        $chunk19 = "9Q" ascii
        $chunk20 = "bH" ascii
        $chunk21 = "dD" ascii
        $chunk22 = "Vm" ascii
        $chunk23 = "5I" ascii
        $chunk24 = "NU" ascii
        $chunk25 = "E5" ascii
        $chunk26 = "QG" ascii
        $chunk27 = "lp" ascii
        $chunk28 = "Lw" ascii
        $chunk29 = "==" ascii
    
    condition:
        10 of them and filesize < 10KB
}

rule SVG_Phishing_Brifutelectric_Temp_Location {
    strings:
        $name1 = "Remittance_Advice" ascii wide
        $name2 = "Remittance" ascii wide
        $name3 = "Advice" ascii wide
        $svg_ext = ".svg" ascii
    
    condition:
        ($name1 or ($name2 and $name3)) and $svg_ext and filesize < 5KB
}