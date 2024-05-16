rule crime_UNC2529_DoubleBack_May2021_1: pedll doubleback {
    meta:
        author = "Nils Kuhnert"
        description = "Triggers on strings and constants used in doubleback samples"
        created = "2021-05-05"
        ref = "https://www.fireeye.com/blog/threat-research/2021/05/unc2529-triple-double-trifecta-phishing-campaign.html"
        hash = "2989581e8a8e3a756ec9af84ff6692526e440349c668e8636e3d10d452995c95"
        hash = "8eada491e7fbd8285407897b678b1a3d480c416244db821cfaca0f27ab27901a"
        hash = "99a0c3a57918273a370a2e9af1dc967e92846821c2198fcdddfc732f8cd15ae1"
        hash = "9d20722758c3f1a01a70ffddf91553b7a380b46b3690d11d8ba4ba3afe75ade0"
        hash = "b3c94fdf4cf16a7d16484976cf8a4abac6d967a7ce8fa4fe9bde3da6d847792f"
        hash = "f58a4f2b319297a256f6b2d77237804c15323dd5e72a0e3a4bfc27cdd0bb0b86"
    strings:
        $x1 = "dbg delay" ascii
        $x2 = "client.dll" ascii fullword

        // Constant init code snippets for 32/64 bit
        $op1 = { b9 4c 64 72 47 c7 8? ?? ?? ?? ?? 65 74 44 6c 57 89 8? ?? ?? ?? ?? c7 8? ?? ?? ?? ?? 6c 48 61 6e c7 8? ?? ?? ?? ?? 64 6c 65 00 e8 ?? ?? ?? ?? 8b f0 89 8? ?? ?? ?? ?? c7 8? ?? ?? ?? ?? 65 74 50 72 c7 8? ?? ?? ?? ?? 6f 63 65 64 c7 8? ?? ?? ?? ?? 75 72 65 41 c7 8? ?? ?? ?? ?? 64 64 72 65 c7 8? ?? ?? ?? ?? 73 73 00 00 }
        $op2 = { c7 44 ?? ?? 65 74 44 6c b9 4c 64 72 47 c7 44 ?? ?? 6c 48 61 6e 41 8b f5 89 4c ?? ?? c7 44 ?? ?? 64 6c 65 00 e8 ?? ?? ?? ?? 4? 8b d8 89 4? ?? c7 4? ?? 65 74 50 72 c7 4? ?? 6f 63 65 64 c7 4? ?? 75 72 65 41 c7 4? ?? 64 64 72 65 c7 4? ?? 73 73 00 00 }
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and all of ($x*) and 1 of ($op*)
}