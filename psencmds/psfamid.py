#!/usr/bin/env python
import sys, re, base64

__author__  = "Jeff White [karttoon] @noottrak"
__email__   = "jwhite@paloaltonetworks.com"
__version__ = "1.0.0"
__date__    = "20NOV2017"

def family_finder(data):

    if data == "Failed to decode":
        family = "N/A"
    else:
        family = "Unknown"

    # Unicorn (forces randomization of $c)
    # https://github.com/trustedsec/unicorn
    #https://raw.githubusercontent.com/trustedsec/social-engineer-toolkit/master/src/powershell/shellcode_injection.powershell
    #https://raw.githubusercontent.com/b00stfr3ak/power-ducky/master/lib/powershell_commands.rb
#    if re.search("\$w \= Add\-Type \-memberDefinition \$[a-zA-Z0-9]{3,4} \-Name", data) or \
#        re.search("\$e \= \[System\.Convert\]::ToBase64String", data) or \
#        re.search(", \$z\[\$i\],", data):

    if re.search("\$w \= Add\-Type \-memberDefinition \$[a-zA-Z0-9]{3,4} \-Name", data):

        if family == "Unknown":
            family = "Unicorn"
        else:
            print "[!] DUPLICATE ERROR Unicorn - %s\n%s" % (family, data)
            sys.exit(1)

    if re.search("\$[a-zA-Z0-9]{5,7} \= \'\[DllImport.+Start\-sleep 60\}\;", data):

        if family == "Unknown":
            family = "Unicorn Modified"
        else:
            print "[!] DUPLICATE ERROR Unicorn Modified - %s\n%s" % (family, data)
            sys.exit(1)

    # ??? SC Injector
    # Looks like borrowed Unicorn prior to randomization
    if re.search("(\$c = |\$1 = [\"\']\$c = )", data) and \
            re.search("\$g = 0x1000", data) and \
            re.search("\$z\.Length \-gt 0x1000", data) and \
            re.search("\$z\[\$i\]", data):

        if family == "Unknown":
            family = "Shellcode Inject"
        else:
            print "[!] DUPLICATE ERROR SC Injector - %s\n%s" % (family, data)
            sys.exit(1)

    # Generic BITS Transfer
    if re.search("Import-Module BitsTransfer", data) and \
            re.search("\$path = \[environment\]::getfolderpath\(\"", data) and \
            re.search("Invoke\-Item  \"\$path", data):

        if family == "Unknown":
            family = "BITSTransfer"
        else:
            print "[!] DUPLICATE ERROR BITS - %s\n%s" % (family, data)
            sys.exit(1)

    # SET
    if re.search("\$code \= [\']{1,2}\[DllImport", data) or \
        re.search("\$sc\.Length -gt 0x1000\)", data) or \
        re.search("\$winFunc::memset", data):

        if family == "Unknown":
            family = "SET"
        else:
            print "[!] DUPLICATE ERROR SET - %s\n%s" % (family, data)
            sys.exit(1)

    # Veil
    # https://github.com/yanser237/https-github.com-Veil-Framework-Veil-Evasion/blob/master/modules/payloads/powershell/shellcode_inject/virtual.py
    if re.search("0x1000,0x3000,0x40", data) or \
            re.search("Start-Sleep -Second 100000", data):

        if family == "Unknown":
            family = "Veil Embed"
        else:
            print "[!] DUPLICATE ERROR Veil Embed - %s\n%s" % (family, data)
            sys.exit(1)

    if re.search("Invoke\-Expression \$\(New\-Object IO\.StreamReader \(\$\(New\-Object IO\.Compression\.DeflateStream", data) and \
            re.search("\)\)\)\), \[IO\.Compression\.CompressionMode\]::Decompress\)\), \[Text\.Encoding\]::ASCII\)\)\.ReadToEnd\(\);", data):

        if family == "Unknown":
            family = "Veil Stream"
        else:
            print "[!] DUPLICATE ERROR Veil Stream - %s\n%s" % (family, data)
            sys.exit(1)

    # Generic Downloader DFSP
    # WebClient -> DownloadFile -> Start-Process
    if re.search("\(New\-Object System\.Net\.WebClient\)\.DownloadFile\((\'|\").+(\'|\"),[\"\'\x1D ]{0,2}.+[\"\'\x1D ]{0,2}\);Start-Process [\(]{0,1}[\"\'\x1D ]{0,2}.+[\"\'\x1D ]{0,2}[\)]{0,1}", data, re.IGNORECASE):

        if family == "Unknown":
            family = "Downloader DFSP"
        else:
            print "[!] DUPLICATE ERROR DFSP - %s\n%s" % (family, data)
            sys.exit(1)

    if re.search("PowerShell \-ExecutionPolicy bypass \-noprofile \-windowstyle hidden \-command \(New\-Object System\.Net\.WebClient\)\.DownloadFile\((\'|\")http[s]{0,1}://.+(\'|\"),[\"\'\x1D ]{0,2}\$env:.+[\"\'\x1D ]{0,2}\);Start-Process \([\"\'\x1D ]{0,2}\$env:.+[\"\'\x1D ]{0,2}\)", data):

        if family == "Unknown":
            family = "Downloader DFSP 2X"
        else:
            print "[!] DUPLICATE ERROR DFSP 2X - %s\n%s" % (family, data)
            sys.exit(1)

    # DeployLocation Downloader
    if re.search("\(\$dpl\=\$env:temp\+.+Start\-Process \$dpl", data) or \
        re.search("\(\$deploylocation\=\$env:temp\+.+Start\-Process \$deploylocation", data):

        if family == "Unknown":
            family = "Downloader DFSP DPL"
        else:
            print "[!] DUPLICATE ERROR DFSP DPL - %s\n%s" % (family, data)
            sys.exit(1)

    # Generic Downloader IEXDS
    # IEX -> DownloadString
    if re.search("IEX [\(]{1,2}New\-Object Net\.WebClient\)\.DownloadString\([\"\'\x1D ]{0,2}.+[\"\'\x1D ]{0,2}[\)]{1,2}[\;]{0,1}", data, re.IGNORECASE):

        if family == "Unknown":
            family = "Downloader IEXDS"
        else:
            print "[!] DUPLICATE ERROR IEXDS - %s\n%s" % (family, data)
            sys.exit(1)

    # PowerWorm
    # https://github.com/mattifestation/PowerWorm/blob/master/PowerWorm_Part_5.ps1
    if re.search("Bootstrapped 100%", data) and \
        re.search("\.onion/get\.php\?s=setup", data):

        if family == "Unknown":
            family = "PowerWorm"
        else:
            print "[!] DUPLICATE ERROR PowerWorm - %s\n%s" % (family, data)
            sys.exit(1)

    # PowerShell Empire
    # https://github.com/EmpireProject/Empire/blob/293f06437520f4747e82e4486938b1a9074d3d51/lib/common/stagers.py#L344
    if re.search("\|\%\{\$\_\-bXor\$k\[\$i\+\+\%\$k\.Length\]\}\;IEX", data, re.IGNORECASE) or \
        re.search("\$Wc\=NeW\-OBJECT SyStem\.NET\.WeBCLient;\$u\=\'Mozilla\/5\.0 \(Windows NT 6\.1; WOW64; Trident\/7\.0; rv:11\.0\) like Gecko\';\$wc\.HeAdeRS\.Add\(\'User\-Agent\',\$u\);\$Wc\.PrOXy \= \[SysTem\.NeT\.WEbReqUesT\]::DEFaulTWebPrOXy;\$wc\.PROxY\.CRedentiALs \= \[SyStEm\.Net\.CredeNtiALCache\]::DefaUlTNetWoRkCReDEntIALS;", data, re.IGNORECASE):

        if family == "Unknown":
            family = "PowerShell Empire"
        else:
            print "[!] DUPLICATE ERROR PowerShell Empire - %s\n%s" % (family, data)
            sys.exit(1)

    # Double Encoding
    # Base64 encoded second command
    if re.search("\-(e|E)[nNcCoOdDeEmMaA]+ [a-zA-Z0-9+/=]{5,}", data):

        if family == "Unknown":
            family = "Encoded 2X"
        else:
            print "[!] DUPLICATE ERROR Encoded 2X - %s\n%s" % (family, data)
            sys.exit(1)

    # Powerfun Bind
    # https://github.com/rapid7/metasploit-framework/blob/cac890a797d0d770260074dfe703eb5cfb63bd46/data/exploits/powershell/powerfun.ps1
    if re.search("New\-Object System\.Net\.Sockets\.TCPClient", data) and \
        re.search("\$sendback2  \= \$sendback \+ \"PS \" \+", data):

        if family == "Unknown":
            family = "Powerfun Bind"
        else:
            print "[!] DUPLICATE ERROR Powerfun Bind - %s\n%s" % (family, data)
            sys.exit(1)

    # Powerfun Reverse
    # Metasploit -p windows/powershell_bind_tcp
    # https://github.com/rapid7/metasploit-framework/pull/5194
    if re.search("\$s\=New\-Object IO\.MemoryStream\(,\[Convert\]::FromBase64String\([\'\"]{1,2}H4sIA[a-zA-Z0-9+/=]+[\'\"]{1,2}\)\)\;IEX \(New\-Object IO\.StreamReader\(New\-Object IO\.Compression\.GzipStream\(\$s,\[IO\.Compression\.CompressionMode\]::Decompress\)\)\)\.ReadToEnd\(\)", data, re.IGNORECASE):
        if family == "Unknown":
            family = "Powerfun Reverse"
        else:
            print "[!] DUPLICATE ERROR Powerfun Reverse - %s\n%s" % (family, data)
            sys.exit(1)

    # Meterpreter Reverse HTTP
    # https://github.com/Arno0x/PowerShellScripts/blob/master/proxyMeterpreterHideout.ps1
    if re.search("windows\/meterpreter\/reverse_http", data, re.IGNORECASE):
        if family == "Unknown":
            family = "Meterpreter RHTTP"
        else:
            print "[!] DUPLICATE ERROR Meterpreter RHTTP - %s\n%s" % (family, data)
            sys.exit(1)

    # PowerSploit Get-TimedScreenshot
    # https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-TimedScreenshot.ps1
    if re.search("function Get\-TimedScreenshot", data) and \
        re.search("#load required assembly", data):
        if family == "Unknown":
            family = "PowerSploit GTS"
        else:
            print "[!] DUPLICATE ERROR PowerSploit GTS - %s\n%s" % (family, data)
            sys.exit(1)

    # https://github.com/PowerShellMafia/PowerSploit/commit/717950d00c7cc352efe8b05c3db84d0e6250474c#diff-8a834e13c96d5508df5ee11bc92c82dd

    # Generic Scheduled Task using COM
    # http://poshcode.org/6690
    if re.search("\$trigger\.StartBoundary \= \$TaskStartTime\.ToString\(\"yyyy-MM-dd\'T\'HH:mm:ss\"\)", data) and \
        re.search("\$service \= new\-object \-ComObject\(\"Schedule\.Service\"\)", data):
        if family == "Unknown":
            family = "Scheduled Task COM"
        else:
            print "[!] DUPLICATE ERROR Scheduled Task COM - %s\n%s" % (family, data)
            sys.exit(1)

    # DynAmite Launcher
    # https://webcache.googleusercontent.com/search?q=cache:yKX6QDiuHHMJ:https://leakforums.net/thread-712268+&cd=3&hl=en&ct=clnk&gl=us
    if re.search("schtasks\.exe \/create \/TN \"Microsoft\\\Windows\\\DynAmite", data) or \
        re.search("#cleanup temp folder", data) or \
        re.search("\"\\\dyna\\\\\"", data):
        if family == "Unknown":
            family = "DynAmite Launcher"
        else:
            print "[!] DUPLICATE ERROR DynAmite Launcher - %s\n%s" % (family, data)
            sys.exit(1)

    # DynAmite keylogger function (old version of PowerSploit Get-Keystrokes)
    # https://github.com/PowerShellMafia/PowerSploit/commit/717950d00c7cc352efe8b05c3db84d0e6250474c#diff-8a834e13c96d5508df5ee11bc92c82dd
    if re.search("Function DynAKey", data):
        if family == "Unknown":
            family = "DynAmite KL"
        else:
            print "[!] DUPLICATE ERROR DynAmite KL - %s\n%s" % (family, data)
            sys.exit(1)

    # TXT C2
    #
    if re.search("if\([\"\']{2}\+\(nslookup \-q=txt", data) and \
        re.search("\) \-match [\"\']{1}@\(\.\*\)@[\"\']{1}\)\{iex \$matches\[1\]\}", data):
        if family == "Unknown":
            family = "TXT C2"
        else:
            print "[!] DUPLICATE ERROR TXT C2 - %s\n%s" % (family, data)
            sys.exit(1)

    # Remove AV
    #
    if re.search("\$uninstall32s = gci", data):
        if family == "Unknown":
            family = "Remove AV"
        else:
            print "[!] DUPLICATE ERROR Remove AV - %s\n%s" % (family, data)
            sys.exit(1)

    # VB Task
    #
    if re.search("\$encstrvbs=", data):
        if family == "Unknown":
            family = "VB Task"
        else:
            print "[!] DUPLICATE ERROR VB Task - %s\n%s" % (family, data)
            sys.exit(1)

    # Remote DLL
    #
    if re.search("regsvr32 \/u \/s \/i:http", data):
        if family == "Unknown":
            family = "Remote DLL"
        else:
            print "[!] DUPLICATE ERROR Remote DLL - %s\n%s" % (family, data)
            sys.exit(1)

    # AMSI Bypass
    #
    if re.search("System\.Management\.Automation\.AmsiUtils.+amsiInitFailed", data, re.IGNORECASE):
        if family == "Unknown":
            family = "AMSI Bypass"
        else:
            print "[!] DUPLICATE ERROR AMSI Bypass - %s\n%s" % (family, data)
            sys.exit(1)

    # Downloader Proxy
    #
    if re.search("\$x\=\$Env:username.+s2\.txt\?u\=", data, re.IGNORECASE):
        if family == "Unknown":
            family = "Downloader Proxy"
        else:
            print "[!] DUPLICATE ERROR Downloader Proxy - %s\n%s" % (family, data)
            sys.exit(1)

    # Downloader Kraken
    #
    if re.search("Kraken\.jpg", data):
        if family == "Unknown":
            family = "Downloader Kraken"
        else:
            print "[!] DUPLICATE ERROR Downloader Kraken - %s\n%s" % (family, data)
            sys.exit(1)

    #if re.search("New\-Object System\.Net\.Sockets\.TCPClient", data) and \
    #    re.search("\$sendback2  \= \$sendback \+ \"PS \" \+", data):
    #    print " ".join([hex(ord(x)) for x in data])
    #    print data
    #    sys.exit(1)

    return family

def main():

    try:
        data = base64.b64decode(sys.argv[1])

    except:

        try:
            fh = open(sys.argv[1], "r")
            data = fh.readlines()
            fh.close()

        except:

            print "Unable to open file or decode base64 input."
            sys.exit(1)

    data = data.replace("\x00", "")
    family = family_finder(data)

    print "\n[+] Family: %s\n" % family

if __name__ == '__main__':
    main()
