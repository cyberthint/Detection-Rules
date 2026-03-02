// ════════════════════════════════════════════════════════
// Kaynak    : Intezer YARA
// Kural     : IPStorm.yar
// Toplanma  : 2026-02-27T23:11:20.442343
// Orijinal  : https://github.com/intezer/yara-rules/blob/master/IPStorm.yar
// ════════════════════════════════════════════════════════

rule IPStorm
{
	meta:
		copyright = "Intezer Labs"
		author = "Intezer Labs"
		reference = "https://www.intezer.com"
	strings:
		$package1 = "storm/backshell"
		$package2 = "storm/filetransfer"
		$package3 = "storm/scan_tools"
		$package4 = "storm/malware-guard"
		$package5 = "storm/avbypass"
		$package6 = "storm/powershell"
		$lib2b = "libp2p/go-libp2p"
		
	condition:
		4 of ($package*) and $lib2b
}
