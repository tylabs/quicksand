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
		mitre = "T1027"

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
		mitre = "T1027"
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
		mitre = "T1027"

	strings:
		$s1 = /Z.{76}ih srpgoar macnntob  eur nniD SOm do/
condition:
            1 of them
}



rule executable_win {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "July 29 2015"
		author = "@tylabs"
		copyright = "tylabs.com 2015"
		desc = "EXE strings"
		mitre = "T1027"

	strings:
		$s1 = "This program cannot be run in DOS mode"
		$s2 = "This program must be run under Win32"
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
		$s15 = "URLDownloadToFileA"
		$s16 = "Advapi32.dll"
		$s17 = "RegOpenKeyExA"
		$s18 = "RegDeleteKeyA"
		$s19 = "user32.dll"
		$s20 = "shell32.dll"
		$s21 = "KERNEL32"
		$s22 = "ExitProcess"
		$s23 = "GetMessageA"
		$s24 = "CreateWindowExA"
		$s25 = {504500004C010100} // PE header
		$s26 = "NtProtectVirtualMemory"
		$s27 = "ntdll.dll"
		$s28 = "CreateWindowExA"
	condition:
            1 of them and not executable_win_pe
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
		mitre = "T1027"

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
		mitre = "T1027"
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
		mitre = "T1027"
	strings:
		$s1 = "edom SOD ni nur eb tonnac margorp sihT" // string.reverse This program cannot be run in DOS mode	condition:
	condition:
            1 of them
}



rule executable_vb {
	meta:
		is_exe = true
		revision = "100"
		rank = 10
		type = "vb"
		date = "July 29 2015"
		author = "@tylabs"
		copyright = "tylabs.com 2015"
		desc = "VB script"
		mitre = "T1059.005"

	strings:
		$s1 = "impersonationLevel=impersonate"
		$s2 = "On Error Resume Next"
		$s3 = "WScript.CreateObject(\"WScript.Shell\")"
		$s4 = "CreateObject(\"Scripting.FileSystemObject\")"
	condition:
            1 of them
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
		mitre = "T1027"


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
