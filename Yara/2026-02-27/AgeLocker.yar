// ════════════════════════════════════════════════════════
// Kaynak    : Intezer YARA
// Kural     : AgeLocker.yar
// Toplanma  : 2026-02-27T23:11:19.415303
// Orijinal  : https://github.com/intezer/yara-rules/blob/master/AgeLocker.yar
// ════════════════════════════════════════════════════════

rule AgeLocker
{
	meta:
		copyright = "Intezer Labs"
		author = "Intezer Labs"
		reference = "https://www.intezer.com"

    strings:
        $a0 = "agelocker.go"
        $a1 = "filippo.io/age/age.go"
        $b0 = "main.encrypt"
        $b2 = "main.stringInSlice"
        $b3 = "main.create_message"
        $b4 = "main.fileExists"


    condition:
        any of ($a*) and any of ($b*)
}
