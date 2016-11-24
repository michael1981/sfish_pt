#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25246);
  script_version("$Revision: 1.56 $");

  script_name(english:"OS Identification : SNMP");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based
on the SNMP data returned." );
 script_set_attribute(attribute:"description", value:
"This script attempts to identify the Operating System type and version by
looking at the SNMP data returned by the remote server." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
  script_summary(english:"Determines the remote operating system");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_family(english:"General");
  script_dependencies("snmp_sysDesc.nasl");
  script_require_keys("SNMP/sysDesc");
  exit(0);
}





if ( ( os = get_kb_item("SNMP/sysDesc")) ) 
{ 
 set_kb_item(name:"Host/OS/SNMP/Fingerprint", value:os);

 if ( os =~ "^Siemens Subscriber Networks [0-9]*-Series")
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Siemens SpeedStream Router");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }
 if ( os =~ "^eCos " )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"eCos Embedded Operating System");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( os =~ "Alpine380[48]" )
 {
 if ( "3804" >< os )
   set_kb_item(name:"Host/OS/SNMP", value:"Extreme Networks Alpine 3804 Switch");
 else
   set_kb_item(name:"Host/OS/SNMP", value:"Extreme Networks Alpine 3808 Switch");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if (  "HUAWEI-3COM WBR-204g" >< os  )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Huawei-3com WBR-204g");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
  exit(0);
 }

 if ("Wireless ADSL WLAN" >< os)
 {
  set_kb_item(name:"Host/OS/SNMP", value:"arcadyan wireless ADSL router");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value: 20);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
  exit(0);
 }

 if ( os =~ "^Prestige ([0-9A-Za-z]*|[-/ ]*)*$" ||
      os =~ "^P-[0-9A-Z]*-[0-9A-Z]*( V[0-9]+)?$" )
 {
  if ( os =~ "^P-" )
	os = ereg_replace(pattern:"^P-", replace:"Prestige ", string:os);
  os = "ZyXEL " + chomp(os) + " ADSL Router";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }
 if ( "Redback Networks SmartEdge OS Version SEOS-" >< os )
 {
  os = egrep(pattern:"^Redback Networks SmartEdge OS Version", string:os);
  os = ereg_replace(pattern:".*SmartEdge OS Version SEOS-(.*)\.Built.*", replace:"SmartEdge OS \1", string:os);
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }

 if ( "Raritan Computer; CommandCenter Secure Gateway" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Raritan CommandCenter Secure Gateway KVM");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0); 
 }
 if ( os =~"FreeBSD.* FreeBSD " )
 {
  os = chomp(ereg_replace(pattern:".*(FreeBSD [0-9.]+[^ ]*).*",string:os, replace:"\1"));
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0); 
 }

 if ( os =~ "VerAg:[0-9._]*;VerSw:[0-9._]*;VerHw:MXe;VerPl:" )
 { 
  os = "Mitel Networks PBX Server";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"pbx");
  exit(0); 
 }
 if ( os =~ "Foundry Networks.*IronWare Version [^ ]*.*" )
 {
  os = "Foundry Networks IronWare " + ereg_replace(pattern:".*IronWare Version ([^ ]*) .*", string:os, replace:"\1");
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0); 
 }
 if ( "ZyWALL" >< os )
 {
  os = "ZyXEL ZyWALL Security Appliance";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"firewall");
  exit(0);
 }
 if ( "Lexmark" >< os )
 {
  os = "Lexmark Printer";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if ("Samsung ML-2850 Series " >< os )
 {
  os = "Samsung ML-2850 Printer";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "This system component provides a complete set of remote management functions for a Server" >< os )
 {
  os = "Dell Remote Access Controller";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( "Fiery " >< os )
 {
  os = "Minolta Fiery Copier";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "TOSHIBA e-STUDIO" >< os )
 {
  ver = ereg_replace(pattern:".*TOSHIBA e-STUDIO([0-9]+).*", string:os, replace:"\1");
  if ( ver == os ) ver = NULL;
  os = "Toshiba e-Studio " + ver + " printer";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "Dell Out-of-band SNMP" >< os )
 {
  os = "Dell Remote Access Controller";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( "Dell Color Laser " >< os || "Dell 3130cn Color Laser" >< os)
 { 
  set_kb_item(name:"Host/OS/SNMP", value:"Dell Color Laser Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "Dell Laser " >< os )
 { 
  set_kb_item(name:"Host/OS/SNMP", value:"Dell Laser Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if ( "3Com SuperStack " >< os )
 {
  os = "3Com SuperStack Switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if ( "3Com SuperStackII " >< os )
 {
  os = "3Com SuperStack II switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 } 

 if ("TigerStack" >< os )
 { 
  os = "SMC TigerStack Switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if ( os =~ "Bay Stack.*hub" )
 {
  os = "Nortel Bay Stack Switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if ( os =~ "^Nortel, CS [0-9]+ Signaling Server" )
 {
  os = "Nortel CS Signaling Server";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
  
 }

 if ("Dell Laser Printer " >< os )
 { 
  os = "Dell Laser Printer";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "Prisma Digital Transport" >< os ) 
 {
   os = "Prisma Digital Transport System";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }
 if ( "RICOH Network Printer C model" >< os )
 {
   os = "Ricoh Printer";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
   exit(0);
 }
 if ( "CMTS" >< os && "Juniper Networks Inc." >< os )
 {
   os = "Juniper CMTS";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }
 if ("Chkpoint/LTX" >< os )
 {
   os = "Check Point/Lantronix Network Adaptor";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }
 if ("Konica IP Controller" >< os )
  {
   os = "Konica IP Controller";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
   exit(0);
  }
 if ("Marconi ASX" >< os )
  {
   os = "Marconi ASX Switch";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
   exit(0);
  }
 if ("CoreBuilder 3500" >< os )
  {
   os = "3Com CoreBuilder 3500 Switch";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
   exit(0);
  }
 if ("Ascend Max-HP" >< os )
  {
   version = ereg_replace(pattern:"Software \+([0-9.]*)\+.*", string:os, replace:"\1");
   os = "Ascend Max-HP Modem Hub " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
  }
  if ( "HP StorageWorks " >< os )
  {
   set_kb_item(name:"Host/OS/SNMP", value:"HP StorageWorks");
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
  }
 if ("LVisual UpTime Multiprotocol T1 CSU DROP & INSERT ASE Ver" >< os )
 {
   version = ereg_replace(pattern:".* ASE Ver ([0-9.]*) .*", string:os, replace:"\1");
   os = "Visual Networks ASE " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }
 if ("ELSA LANCOM" >< os )
 {
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
   exit(0);
 }
 if ("IP Console Switch " >< os )
 {
   set_kb_item(name:"Host/OS/SNMP", value:"HP " + os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }
 if ("SCO UnixWare" >< os )
 {
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
 }
 if ( "SCO TCP/IP Runtime Release " >< os )
 {
   set_kb_item(name:"Host/OS/SNMP", value:"SCO OpenServer");
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:75);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
 }

 if ("Apple Base Station" >< os )
 {
   version = ereg_replace(pattern:".*Apple Base Station V(.*) Compatible",
			  replace:"\1",
			  string:os);
 
   os = "Apple Airport " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
   exit(0);
 }

 if ( "Apple AirPort" >< os )
 {
  os = "Apple AirPort Extreme Base Station";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
  exit(0);
 }

 if ("OpenVMS" >< os )
 {
  version = ereg_replace(pattern:".*OpenVMS V([0-9]*\.[0-9]*).*", 
			 string:egrep(pattern:"OpenVMS", string:os),
			 replace:"\1");
  if ( version != os )
  {
   os = "OpenVMS " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
  }

   
 }
 if ("IBM Gigabit Ethernet Switch Module" >< os )
 {
   os = "IBM Gigabit Ethernet Switch Module";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
   exit(0);
 }

 if (os =~ "^WJ-HD300 SWVer[0-9]\.[0-9]+")
 {
   os = strcat("Panasonic Digital ", os);
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value: 100);
   set_kb_item(name:"Host/OS/SNMP/Type", value: "embedded");
   exit(0);
 }

 if (os == "Ultrium Tape Library Specialist")
 {
   os = "IBM Ultrium Table Library";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value: 99);
   set_kb_item(name:"Host/OS/SNMP/Type", value: "embedded");
   exit(0);
 }

 if ( os =~ "^Cisco Controller" )
 {
   set_kb_item(name:"Host/OS/SNMP", value:"Cisco Wireless Controller");
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point");
   exit(0);
 }
 if ( "IOS (tm)" >< os  || "Cisco IOS Software" >< os )
 {
  version = ereg_replace(pattern:".*IOS.*Version ([0-9]*\.[0-9]*\([0-9a-zA-Z]+\)[A-Z0-9.]*),.*",
			 string:egrep(pattern:"IOS", string:os),
			 replace:"\1");

  if ( version != os )
  {
   os = "CISCO IOS " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
   exit(0);
  }
 }

 if ("Cisco Systems, Inc./VPN 3000 Concentrator " >< os)
 {
   v = eregmatch(string: os, pattern: "^Cisco Systems, Inc./VPN 3000 Concentrator Version ([0-9]\.[0-9A-Z.]+)");
   if (isnull(v))
     os = "CISCO VPN Concentrator";
   else
     os = strcat("CISCO VPN Concentrator Version ", v[1]);
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"VPN");
   exit(0);
 }

 if ("Digital UNIX" >< os )
 {
  version = ereg_replace(pattern:".*Digital UNIX V([0-9]\.[0-9]).*",
			 string:egrep(pattern:"Digital UNIX", string:os),
			 replace:"\1");
  if ( version != os )
  {
   os = "Digital Unix " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
  }
 }


 if ("ULTRIX" >< os )
 {
  version = ereg_replace(pattern:".*ULTRIX V([^ ]*).*", 
			 string:egrep(pattern:"ULTRIX", string:os), 
			 replace:"\1");
  if ( version != os ) 
  {
   os = "ULTRIX " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
  }
 }
 if ("HP-UX" >< os )
 {
   version = ereg_replace(pattern:".*HP-UX [^ ]* ([^ ]*) .*", 
			  replace:"\1", 
			  string:egrep(pattern:"HP-UX", string:os)
			 );
   if ( version != os )
   {
   set_kb_item(name:"Host/OS/SNMP", value:"HP/UX " + version);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
   }
 }

 # HP3000 SERIES e3000/A500-100-14, MPE XL version C.70.02 NS Transport version B.07.00
 if ("HP3000 " >< os && " MPE " >< os)
 {
   v = eregmatch(string: os, pattern: "HP3000 .* MPE (iX|XL version [^ ]+) ");
   if (! isnull(v))
   {
     set_kb_item(name:"Host/OS/SNMP", value:"HP 3000 - MPE/" + v[1]);
     set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
     set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   }
   else
   {
     set_kb_item(name:"Host/OS/SNMP", value:"HP 3000 - MPE/XL\nHP 3000 - MPE/iX\n");
     set_kb_item(name:"Host/OS/SNMP/Confidence", value: 75);
     set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   }
   exit(0);
 }

 if ( "IBM Infoprint " >< os )
 {
   os = "IBM Infoprint server " + ereg_replace(pattern:".*IBM Infoprint ([0-9]+).* [Vv]ersion ([0-9A-Z.]+).*", replace:"\1 Version \2", string:os);

   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
   exit(0);
 }

 if ("TGNet PSIO" >< os )
 {
  version = "TGNet Printer";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ("JETDIRECT" >< os || "HP ETHERNET MULTI-ENVIRONMENT" >< os )
 {
  version = "HP JetDirect Printer";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 } 
 if ( "Lantronix UDS" >< os )
 {
  version = "Lantronix Universal Device Server";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( os =~ "ProCurve .*Switch" )
 {
  version = "HP ProCurve Switch";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 } 

 if (os =~ "^KYOCERA.*Print" )
 {
  version = "KYOCERA Printer";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( os =~ "^OKI OkiLAN 8100e" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"EthernetBoard OkiLAN 8100e");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 } 
 if ("Xerox" >< os || os =~ "XEROX.*Printer" || os =~ "XEROX DocuPrint" )
 {
  version = "Xerox Printer";
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if ("NetQue" >< os )
 {
  report = "The remote host is running NetQue Printer Server";
  set_kb_item(name:"Host/OS/SNMP", value:"NetQue Printer Server");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 # http://www.dealtime.co.uk/xPF-Equinox_MDS_10_990410
 if ("EQUINOX MDS" >< os )
 {
  os = "Equinox MDS Transceiver";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if ("Novell NetWare" >< os )
 {
  version = ereg_replace(pattern:".* NetWare ([^ ]*).*", string:os, replace:"\1");
  if ( version != os ) 
  {
  version = split(version, sep:'.', keep:0);
  os = "Novell Netware " + int(version[0]) + "." + int(version[1]) / 10; 
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
  }
 }


 if ("WorkCentre Pro Multifunction System" >< os )
 {
  os = "Xerox WorkCentre Pro"; 
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if ( os =~ "SunOS .* 5\." )
 {
  snmp = os;
  os = "Solaris " + ereg_replace(pattern:"^SunOS .* 5\.([0-9]+) .*", string:os, replace:"\1");
  if ( "i86pc" >< snmp ) os += " (i386)";
  else os += " (sparc)";
  
  
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:99);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
 }

 if ( "Sun SNMP Agent" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Solaris");
  # Set the confidence to 5 because we can't distinguish the version of Solaris
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:5);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
 }

 if ( os =~ "^Microsoft Windows CE Version" )
 {
  version = ereg_replace(pattern:"^Microsoft Windows CE Version ([^ ]*).*", replace:"\1", string:os);
  set_kb_item(name:"Host/OS/SNMP", value:"Microsoft Windows CE Version " + version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:95);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 
 }
 if ( os == "Microsoft Corp. Windows 98.")
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Microsoft Windows 98");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
 }
 if ( os =~  "Hardware:.*Software: Windows " )
 {
  os2 = ereg_replace(pattern:".*Software: Windows .*Version ([0-9.]+).*", string:os, replace:"\1");
  if ( os2 != os )
  {
   if ( os2 == "4.0" )
    os = "Microsoft Windows NT 4.0";
   else if ( os2 == "5.0" )
    os = "Microsoft Windows 2000";
   else if ( os2 == "5.1" )
    os = "Microsoft Windows XP";
   else if (os2 == "5.2" )
    os = "Microsoft Windows Server 2003";
   else exit(0);
 
   # 
   # Confidence level is 75 : pretty confident, but we do not have the Service Pack ID
   #
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:75);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
  }
 }

 if ("AIX" >< os )
 {
  line = egrep(pattern:"AIX version", string:os);
  version = ereg_replace(pattern:".*AIX version ?: (.*)$", string:line, replace:"\1");
  if ( version != line )
  {
  version = split(version, sep:'.', keep:0);
  os = "AIX " + int(version[0]) + "." + int(version[1]);
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
  }
 }

 if ( os == "Videoconferencing Device" || os == "Video Conferencing Device" ||
      os == "Videoconf Device" )
 {
   os = "Polycom Teleconferencing Device";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:85);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }

 if (os == "NetPort Software 1.1")
 {
   os = "Polycom Teleconferencing Device";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value: 71);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
   exit(0);
 }

 if (os =~ "^Juniper Networks.*E320 Edge Routing Switch" ) 
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Juniper E320 Edge Routing Switch");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }

 if ( "Juniper SR-" >< os || "Peribit SR-" >< os )
 {
  ver = ereg_replace(pattern:".*SR-([0-9]*).*", replace:"\1", string:os);
  os = "Juniper Peribit SR-" + ver;
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"packet-shaper");
  exit(0);
 }

 # NetEnforcerSGBS - Application Bandwidth Manager
 # AC - Application Bandwidth Manager
 if ( " - Application Bandwidth Manager" >< os  )
 {
   set_kb_item(name:"Host/OS/SNMP", value:"NetEnforcer Application Bandwidth Manager");
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"packet-shaper");
   exit(0);
 }

 if ( os =~ "Tru64 UNIX V[0-9.]+" )
 {
  version = ereg_replace(pattern:".*Tru64 UNIX V([0-9.]+).*", replace:"\1", string:os);
  if ( version != os ) 
  {
   os = "Tru64 Unix Version " + version;
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
  }
 }
 if ( os =~ "Enterasys Networks, Inc. Matrix N[0-9]* Platinum")
 {
   os = "Enterasys Networks Matrix N-Series Platinium";
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
   exit(0);
 }
 
 if ( "NetApp Release " >< os )
 {
  os = "NetApp Release " + ereg_replace(pattern:".*Release ([0-9.]+).*", replace:"\1", string:os);
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 
 if ( "DSR2035 " >< os )
 {
  os = "DSR2035 KVM Switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( "Darwin Kernel Release" >< os )
 {
   os = ereg_replace(string:os, pattern:".*Darwin Kernel Release Version ([0-9.]+).*", replace:"\1");
   num = split(os, sep:".", keep:FALSE);
   version = "Mac OS X 10." + string(int(num[0]) - 4) + "." + num[1];
   set_kb_item(name:"Host/OS/SNMP", value:os);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
 }

 if ( "Darwin Kernel Version" >< os )
 {
   os = ereg_replace(string:os, pattern:".*Darwin Kernel Version ([0-9.]+).*", replace:"\1");
   num = split(os, sep:".", keep:FALSE);
   version = "Mac OS X 10." + string(int(num[0]) - 4) + "." + num[1];
   set_kb_item(name:"Host/OS/SNMP", value:version);
   set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
   set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
   exit(0);
 }

 if ( os =~ "^Linux " )
 {
  version = ereg_replace(pattern:"Linux [^ ]* (2\.[^ ]*).*", replace:"\1", string:os);
  if ( version != os ) 
  {
  version = "Linux Kernel " + version;
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
  }
 }
 if ( "kernel 2." >< os )
 {
  version = ereg_replace(pattern:".* kernel (2\.[0-9])\..*", replace:"\1", string:os);
  if ( version != os ) 
  {
  version = "Linux Kernel " + version;
  set_kb_item(name:"Host/OS/SNMP", value:version);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose");
  exit(0);
  }
 }

 if ("Modbus/TCP to RTU Bridge" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Modbus/TCP to RTU Bridge");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded"); # scada-embedded?
  exit(0);
 }
 if ("NetBotz RackBotz 400 Appliance" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"NetBotz RackBotz 400 Appliance");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded"); 
  exit(0);
 }

 if ( os =~ "Fibre Channel Switch" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Brocade Fibre Channel Switch");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch"); 
  exit(0);
 }
 if  ("ProCurve Access Point" >< os )
 {
  os = ereg_replace(pattern:"ProCurve Access Point ([^ ]*).*", string:os, replace:"\1");
  set_kb_item(name:"Host/OS/SNMP", value:"HP ProCurve Access Point " + os );
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"wireless-access-point"); 
  exit(0);
 }

 if ("NCD ThinSTAR " >< os )
 {
  os = ereg_replace(pattern:"NCD ThinSTAR [^ ]*.*", string:os, replace:"\1");
  set_kb_item(name:"Host/OS/SNMP", value:"NCD ThinSTAR " + os );
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"general-purpose"); # embedded?
  exit(0);
 }
 if ( "Fluke Networks OptiView (tm) Integrated Network Analyzer" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Fluke Optiview Network Analyzer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if ("Canon iR C3200" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Canon imageRunner C3200 Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if ("Canon LBP" >< os )
 {
   num = ereg_replace(string:os, pattern:"^Canon LBP([0-9]+) .*", replace:"\1");
   if ( num == os ) num = "";
  set_kb_item(name:"Host/OS/SNMP", value:"Canon LBP" + num + " Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if ( "Alcatel SPEEDTOUCH" >< os || os =~ "^SpeedTouch" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Alcatel SpeedTouch DSL Modem");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if (os =~ "Digi International PortServer" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Digi International PortServer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if (os =~ "^BEFSX" )
 {
  os = "Linksys BEFSX Router";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }
 if (os =~ "^PROCURVE ")
 {
  os = "HP ProCurve Switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if ( os =~ "^Passport-[0-9]"  )
 {
  os = "Nortel Passport Switch";
  set_kb_item(name:"Host/OS/SNMP", value:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }
 if ( os =~ "^Netopia [0-9]*.* v[0-9.]*[A-Z0-9.]*")
 {
  os = ereg_replace(pattern:"^Netopia ([^ ]*).*", replace:"Netopia \1 Router", string:os);
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }
 if ( os =~ "^KONICA MINOLTA" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Konica Minolta Digital Copier/Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }

 if (os =~ "^Minolta Di[0-9]+$")
 {
  set_kb_item(name:"Host/OS/SNMP", value: os + " Digital Copier/Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
  set_kb_item(name:"Host/OS/SNMP/Type", value: "printer");
  exit(0);
 }

 if ( os =~ "^EPSON.*Print Server" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"EPSON Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:90);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( os =~ "Brother NC-.*Firmware")
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Brother Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( os =~ "SHARP AR-M[1-9][0-9][0-9]")
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Sharp Printer");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"printer");
  exit(0);
 }
 if ( "ALCATEL VoIP terminal" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Alcatel VoIP terminal");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( os =~ "^Cayman-DSL" )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Cayman DSL Router");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"router");
  exit(0);
 }

 if ("ADSL Router, VxWorks SNMPv1/v2c Agent, Conexant System, Inc. " >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Conexant ADSL Modem");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 } 
 if ( "3COM VCX Server" >< os )
 { 
  set_kb_item(name:"Host/OS/SNMP", value:"3com VCX VoIP Server");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:98);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 if ( "Packeteer PacketShaper " >< os )
 { 
  set_kb_item(name:"Host/OS/SNMP", value:"Packeteer PacketShaper");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"packet-shaper");
  exit(0);
 }

 if ( "Lucent Technologies Cajun Switch Agent " >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Lucent Switch");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }

 if ( "APC Environmental Monitoring Unit" >< os )
 {
  #http://www.apc.com/products/family/index.cfm?id=47
  set_kb_item(name:"Host/OS/SNMP", value:"APC Environmental Monitoring Unit");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }

 if ( os =~ "^BayStack " )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"Nortel Baystack Switch");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"switch");
  exit(0);
 }

 if ("VMware ESX Server" >< os && "VMware, Inc." >< os)
 {
  set_kb_item(name:"Host/OS/SNMP", value:"VMware ESX");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"hypervisor");
  exit(0);
 }

 if ( "DynaStar 500" >< os )
 {
  set_kb_item(name:"Host/OS/SNMP", value:"DynaStar 500");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
 
 if ("VxWorks" >< os ) # Must be last
 {
  set_kb_item(name:"Host/OS/SNMP", value:"VxWorks");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:75);
  set_kb_item(name:"Host/OS/SNMP/Type", value:"embedded");
  exit(0);
 }
}
