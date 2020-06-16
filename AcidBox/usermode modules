import "pe"

rule acidbox_usermode_modules {
    meta:
        author = "Dominik Reichel"
        description = "Detects Windows AcidBox SSP and main worker modules"
        date = "2020/06/16"
        hash0 = "eb30a1822bd6f503f8151cb04bfd315a62fa67dbfe1f573e6fcfd74636ecedd5"
        hash1 = "b3166c417d49e94f3d9eab9b1e8ab853b58ba59f734f774b5de75ee631a9b66d"
        hash2 = "3ad20ca49a979e5ea4a5e154962e7caff17e4ca4f00bec7f3ab89275fcc8f58c"
        hash3 = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"

    strings:
        // Status codes
        $a0 = {01 04 00 A0}
        $a1 = {02 04 00 A0}
        $a2 = {06 04 00 A0}
        $a3 = {01 06 03 80}
        $a4 = {02 06 03 80}
        $a5 = {03 06 03 80}
        $a6 = {02 07 05 80}
        $a7 = {04 07 05 80}
        $a8 = {06 07 05 80}
        $a9 = {02 0C 07 80}
        $a10 = {06 0C 07 80}
        $a11 = {01 02 08 A0}
        $a12 = {02 02 08 A0}
        $a13 = {04 02 08 A0}
        $a14 = {06 02 08 A0}

        // Byte markers
        $a15 = {9A 65 65 9A}
        $a16 = {DE AD BE EF}
        $a17 = {DE AD FE ED}
        $a18 = {DE AD BA FA}
        $a19 = {BA BA B0 0E}
        $a20 = {99 EE EE 44}
        $a21 = {BA AD D0 0D}

        // Cleartext strings
        $b0 = "%s\\[[%s]]"
        $b1 = "%s%s%s.dll"
        $b2 = "\\\\.\\PCIXA_CFGDEV"
        $b3 = "InitEntry"
        $b4 = "InitExit"
        $b5 = "The Magic Word!"
        $b6 = "ntoskrnl.exe"
        $b7 = "hal.dll"
        $b8 = "ntkrnlpa.exe"
        $b9 = "Root\\LEGACY_NULL\\0000"
        $b10 = "%s\\%s"
        $b11 = "%s\\%s{%s}"
        $b12 = "%s\\{%s}"

        // Last bytes of icon + marker bytes of appended data
        $c0 = {80 00 00 03 80 00 00 03 80 00 00 03 80 00 00 03 56 89 69 B6}

    condition:
        uint16(0) == 0x5A4D and
        all of ($a*) or
        all of ($b*) or
        (
            15 of ($a*) and
            5 of ($b*)
        ) or
        (
            5 of ($a*) and
            2 of ($b*) and
            pe.exports("InitMainStartup") and
            pe.exports("UpdateContext")
        ) or
        (
            pe.exports("InitPhysicalInterfaceA") and
            pe.exports("SpLsaModeInitialize") and
            pe.exports("UpdateSecurityContext") and
            pe.exports("InitSecurityInterfaceA")
        ) or
        (
            15 of ($a*) and
            $c0
        )
}
