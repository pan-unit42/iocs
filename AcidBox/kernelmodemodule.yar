import "pe"

rule acidbox_kernelmode_module {
    meta:
        author = "Dominik Reichel"
        description = "Detects Windows AcidBox kernelmode driver"
        date = "2020/06/16"
        hash = "3ef071e0327e7014dd374d96bed023e6c434df6f98cce88a1e7335a667f6749d"

    strings:
        // Status codes
        $a0 = {03 0D 06 A0}
        $a1 = {06 0D 06 A0}
        $a2 = {0A 0D 06 A0}
        $a3 = {02 10 06 A0}
        $a4 = {03 10 06 A0}
        $a5 = {07 10 06 A0}
        $a6 = {09 10 06 A0}
        $a7 = {01 1A 06 A0}
        $a8 = {02 1A 06 A0}
        $a9 = {03 1A 06 A0}
        $a10 = {07 1A 06 A0}
        $a11 = {09 1A 06 A0}
        $a12 = {02 1B 06 A0}
        $a13 = {03 1B 06 A0}

        // Byte markers
        $a14 = {DE AD BE EF}
        $a15 = {DE AD FE ED}
        $a16 = {DE AD BA FA}

        // ASCII cleartext strings
        $b0 = "ntoskrnl.exe"
        $b1 = "ntkrn"
        $b2 = "ntkrp"
        $b3 = "hal.dll"
        $b4 = "ntkrnlpa.exe"
        $b5 = "csrss.exe"

        // Unicode cleartext strings
        $c0 = "\\Device\\VBoxDrv" wide
        $c1 = "\\DosDevices\\PCIXA_CFGDEV" wide
        $c2 = "\\Windows\\ApiPort" wide
        $c3 = "\\Sessions\\%u\\Windows\\ApiPort" wide
        $c4 = "\\Sessions\\xxxxxxxx\\Windows\\ApiPort" wide
        $c5 = "\\Device\\PCIXA_CFG" wide
        $c6 = "\\DosDevices\\PCIXA_CFGDEV" wide

    condition:
        uint16(0) == 0x5A4D and
        all of ($a*) or
        all of ($c*) or
        (
            10 of ($a*) and
            all of ($b*)
        ) or
        (
            10 of ($a*) and
            5 of ($b*) or
            5 of ($c*)
        ) or
        (  
            10 of ($a*) and
            pe.exports("InitEntry") and
            pe.exports("InitExit")
        )
}
