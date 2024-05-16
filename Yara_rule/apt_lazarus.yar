rule apt_Lazarus_Job_Lure_May2021_1: doc lazarus macros {
    meta:
        author = "Nils Kuhnert"
        description = "Triggers on macro strings used in Lazarus lure."
        hash = "e6dff9a5f74fff3a95e2dcb48b81b05af5cf5be73823d56c10eee80c8f17c845"
    strings:
        $s1 = "\\DriverUpdateCheck.exe" ascii
        $s2 = "Scripting.FileSystemObject" ascii
        $s3 = "Wscript.Shell" ascii fullword
        $s4 = "c:\\Drivers" ascii 
        $s5 = "\\DriverGFE.tmp" ascii 
        $s6 = "\\DriverGFXCoin.tmp" ascii 
        $s7 = "\\DriverCPHS.tmp" ascii 
        $s8 = "DriverGFX.tmp" ascii
    condition:
        uint32(0) == 0xe011cfd0 and filesize > 1MB and filesize < 5MB and 5 of them
}

rule apt_Lazarus_Job_DLL_May2021_1: pe lazarus {
    meta:
        author = "Nils Kuhnert"
        description = "Triggers on strings used in Lazarus DLL during on of their \"job\" campaigns."
        hash = "5c206b4dc2d3a25205176da9a1129c9f814c030a7bac245e3aaf7dd5d3ca4fbe"
    strings:
        $s1 = "%04d-%02d-%02dT%02d:%02d:%02d" wide
        $s2 = "%04d-%02d-%02dT%02d:%02d:00" wide
        $s3 = "%s,updateCache" wide
        $s4 = "rundll32.exe" wide fullword
        $s5 = "Office Feature Updates Task" wide
        $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36" ascii
        $s7 = "https://wicall.ir/logo.png" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 250KB and 6 of them
}