/* https://github.com/tylabs/quicksand Executable detection signatures 
 * v   */

rule executable_win_pe {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "Dec 27 2015"
		author = "@tylabs"
		desc = "MZ Header"
		copyright = "tylabs.com 2015"
		mitre = "T1027 T1027.009"

	strings:
		$s1 = /MZ.{76}This program /
condition:
            1 of them
}

rule executable_win_pe_transposed {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "Dec 27 2015"
		author = "@tylabs"
		desc = "MZ Transposed"
		mitre = "T1027 T1027.013"
		copyright = "tylabs.com 2015"

	strings:
		$s1 = /ZM.{76}hTsip orrgma/
condition:
            1 of them
}


rule executable_win_pe_transposed_offbyone {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "Dec 27 2015"
		author = "@tylabs"
		desc = "MZ transposed and shifted"
		copyright = "tylabs.com 2015"
		mitre = "T1027 T1027.013"

	strings:
		$s1 = /Z.{76}ih srpgoar macnntob  eur nniD SOm do/
condition:
            1 of them
}



rule executable_win {
	meta:
		is_exe = true
		type = "win"
		revision = "101"
		rank = 10
		date = "Nov 9 2026"
		author = "@tylabs"
		copyright = "tylabs.com 2026"
		desc = "EXE strings"
		mitre = "T1027 T1027.009"

	strings:
		$dos1 = "This program cannot be run in DOS mode"
		$dos2 = "This program must be run under Win32"
		$pe_hdr = {504500004C010100} // PE32 header
		$pe64_hdr = {504500006486}   // PE64 header
		$s4 = "LoadLibraryA"
		$s5 = "GetModuleHandleA"
		$s6 = "GetCommandLineA"
		$s7 = "GetSystemMetrics" 
		$s8 = "GetProcAddress"
		$s9 = "CreateProcessA"
		$s10 = "URLDownloadToFileA"
		$s11 = "EnterCriticalSection"
		$s12 = "GetEnvironmentVariableA"
		$s13 = "CloseHandle"
		$s14 = "CreateFileA"
		$s16 = "Advapi32.dll"
		$s17 = "RegOpenKeyExA"
		$s18 = "RegDeleteKeyA"
		$s19 = "user32.dll"
		$s20 = "shell32.dll"
		$s21 = "KERNEL32"
		$s22 = "ExitProcess"
		$s23 = "GetMessageA"
		$s24 = "CreateWindowExA"
		$s26 = "NtProtectVirtualMemory"
		$s27 = "ntdll.dll"
	condition:
            (1 of ($dos*) or 1 of ($pe*) or 3 of ($s*)) and not executable_win_pe
}




rule executable_win_transposed {
	meta:
		is_exe = true
		type = "win-tp"
		revision = "100"
		rank = 10
		date = "July 29 2015"
		desc = "Transposition cipher"
		author = "@tylabs"
		copyright = "tylabs.com 2015"
		mitre = "T1027 T1027.013"

	strings:
		$s1 = "hTsip orrgmac naon tebr nui  nOD Somed" //string.transposition cipher of This program cannot be run in DOS mode
	condition:
            1 of them and not executable_win_pe_transposed
}

rule executable_win_rtl {
	meta:
		is_exe = true
		type = "win-rtl"
		rank = 10
		revision = "100"
		date = "July 29 2015"
		desc = "Right to Left compression LZNT1"
		author = "@tylabs"
		copyright = "tylabs.com 2015"
		mitre = "T1027 T1027.013"
	strings:
		$s1 = {2070726F6772616D002063616E6E6F74200062652072756E2069006E20444F53206D6F} // string.RTL.This program cannot be run in DOS mode
	condition:
            1 of them
}

rule executable_win_reversed {
	meta:
		is_exe = true
		type = "win-reversed"
		rank = 10
		revision = "100"
		date = "July 29 2015"
		desc = "EXE is stored backwards"
		author = "@tylabs"
		copyright = "tylabs.com 2015"
		mitre = "T1027 T1027.013"
	strings:
		$s1 = "edom SOD ni nur eb tonnac margorp sihT" // string.reverse This program cannot be run in DOS mode	condition:
	condition:
            1 of them
}



rule executable_vb {
	meta:
		is_exe = true
		revision = "101"
		rank = 8
		type = "vb"
		date = "Nov 9 2026"
		author = "@tylabs"
		copyright = "tylabs.com 2026"
		desc = "VB script"
		mitre = "T1059.005"

	strings:
		$s1 = "impersonationLevel=impersonate" nocase
		$s2 = "WScript.CreateObject(\"WScript.Shell\")" nocase
		$s3 = "CreateObject(\"Scripting.FileSystemObject\")" nocase
		$s4 = "WScript.Sleep" nocase
		$s5 = "WScript.Quit" nocase
	condition:
            1 of ($s1, $s2) or 2 of ($s3, $s4, $s5)
}


rule executable_macosx {
	meta:
		is_exe = true
		type = "macosx"
		revision = "100"
		rank = 10
		date = "July 29 2015"
		author = "@tylabs"
		copyright = "tylabs.com 2015"
		desc = "Mac executable"
		mitre = "T1027 T1027.009"


	strings:
		$s1 = "<key>RunAtLoad</key>"
		$s2 = "__mh_execute_header"
		$s3 = "/Developer/SDKs/MacOSX10.5.sdk/usr/include/libkern/i386/_OSByteOrder.h"
		$s4 = "__gcc_except_tab__TEXT"
		$s5 = "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices"
		$s6 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
		$s7 = "@_getaddrinfo"
		$s8 = "@_pthread_create"
		$s9 = "StartupParameters.plist"
		$s10 = "dyld__mach_header"
		$s11 = "/usr/lib/libSystem"
		$s12 = "/usr/lib/dyld"
		$s13 = "__PAGEZERO"
		$s14 = "/usr/lib/libgcc_s"
	condition:
            1 of them
}

rule executable_unhandled_compression {
	meta:
		is_exe = true
		revision = "1"
		rank = 2
		type = "compression"
		date = "May 28 2025"
		author = "@tylabs"
		copyright = "tylabs.com 2025"
		desc = "compression script"
		mitre = "T1027.015"

	 strings:
	    // .7z (7-Zip)
	    $7z_magic = { 37 7A BC AF 27 1C }
	
	    // .tar (Tape Archive) - Often starts with a specific header, but can be less reliable than others.
	    // This is a common pattern for the 'ustar' header.
	    $tar_magic = { 75 73 74 61 72 00 30 30 } // "ustar\000"
	
	    // .rar (RAR archive)
	    $rar_magic_v1 = { 52 61 72 21 1A 07 00 } // RAR 1.50 onwards
	    $rar_magic_v2 = { 52 61 72 21 1A 07 01 00 } // RAR 5.00 onwards
	
	    // .gz / .gzip (GNU Zip)
	    $gz_magic = { 1F 8B }
	
	    // .bzip2 (BZip2)
	    $bzip2_magic = { 42 5A 68 } // "BZh"
	
	    // .wim (Windows Imaging Format)
	    $wim_magic = { 4D 53 57 49 4D } // "MSWIM"
	
	    // .xz (XZ Utils)
	    $xz_magic = { FD 37 7A 58 5A 00 }
	
	  condition:
	    $7z_magic at 0 or
	    $tar_magic at 0 or
	    $rar_magic_v1 at 0 or
	    $rar_magic_v2 at 0 or
	    $gz_magic at 0 or
	    $bzip2_magic at 0 or
	    $wim_magic at 0 or
	    $xz_magic at 0
}

rule executable_encoded_pe {
	meta:
		is_exe = true
		revision = "1"
		rank = 10
		type = "win-encoded"
		date = "Nov 9 2026"
		author = "@tylabs"
		copyright = "tylabs.com 2026"
		desc = "Base64 or Hex encoded Windows PE executable"
		mitre = "T1027 T1027.013"
	strings:
		$b64_1 = "TVqQAAMAAAAEAAAA" ascii wide
		$b64_2 = "TVpQAAIAAAAEAA8A" ascii wide
		$b64_3 = "TVroAAAAAAA" ascii wide
		$hex_1 = "4d5a90000300000004000000ffff0000" nocase ascii wide
		$hex_2 = "546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f6465" nocase ascii wide
	condition:
		any of them
}

rule executable_lnk_shortcut {
	meta:
		is_exe = true
		revision = "1"
		rank = 8
		type = "lnk"
		date = "Nov 9 2026"
		author = "@tylabs"
		copyright = "tylabs.com 2026"
		desc = "Embedded Windows LNK shortcut executing command or script"
		mitre = "T1204.002 T1059.003 T1547.009"
	strings:
		$lnk_hdr = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$cmd1 = "cmd.exe" nocase ascii wide
		$cmd2 = "powershell" nocase ascii wide
		$cmd3 = "mshta" nocase ascii wide
		$cmd4 = "rundll32" nocase ascii wide
		$cmd5 = "regsvr32" nocase ascii wide
		$cmd6 = "wscript" nocase ascii wide
		$cmd7 = "cscript" nocase ascii wide
		$cmd8 = "certutil" nocase ascii wide
	condition:
		$lnk_hdr and 1 of ($cmd*)
}

rule executable_scriptlet_hta_sct {
	meta:
		is_exe = true
		revision = "1"
		rank = 8
		type = "scriptlet"
		date = "Nov 9 2026"
		author = "@tylabs"
		copyright = "tylabs.com 2026"
		desc = "Embedded HTA or COM Scriptlet payload"
		mitre = "T1218.005 T1218.010"
	strings:
		$hta = "<hta:application" nocase ascii wide
		$sct1 = "<scriptlet" nocase ascii wide
		$sct2 = "<registration" nocase ascii wide
		$act1 = "ActiveXObject" nocase ascii wide
		$act2 = "WScript.Shell" nocase ascii wide
		$act3 = "GetObject(\"script:" nocase ascii wide
	condition:
		($hta and 1 of ($act*)) or ($sct1 and ($sct2 or 1 of ($act*)))
}

rule executable_elf {
	meta:
		is_exe = true
		revision = "1"
		rank = 10
		type = "elf"
		date = "Nov 9 2026"
		author = "@tylabs"
		copyright = "tylabs.com 2026"
		desc = "ELF executable header"
		mitre = "T1027 T1027.009"
	strings:
		$elf = { 7F 45 4C 46 (01 | 02) (01 | 02) 01 }
	condition:
		$elf at 0
}

rule executable_container_disk_image_cab {
	meta:
		is_exe = true
		revision = "1"
		rank = 6
		type = "container"
		date = "Nov 12 2026"
		author = "@tylabs"
		copyright = "tylabs.com 2026"
		desc = "Embedded ISO/UDF/VHD/VHDX disk image or CAB container (Mark-of-the-Web bypass)"
		mitre = "T1553.005 T1204.002"
	strings:
		$iso_cd001 = "CD001" ascii
		$udf_bea01 = { 00 42 45 41 30 31 01 }
		$vhd_hdr = "conectix" ascii
		$vhdx_hdr = "vhdxfile" ascii
		$cab_hdr = { 4D 53 43 46 00 00 00 00 }
	condition:
		$iso_cd001 at 0x8001 or
		$iso_cd001 at 0x8801 or
		$udf_bea01 at 0x8000 or
		$vhd_hdr at 0 or
		$vhdx_hdr at 0 or
		$cab_hdr at 0
}

