#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25244);
  script_version("$Revision: 1.21 $");

  name["english"] = "OS Identification : NTP";
  script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based
on the data returned by the NTP server." );
 script_set_attribute(attribute:"description", value:
"This script attempts to identify the Operating System type 
and version by looking at the NTP data returned by the remote 
server." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
  summary["english"] = "Determines the remote operating system";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencies("ntp_open.nasl");
  script_require_keys("Host/OS/ntp");
  exit(0);
}


#
# If NTP is open, try to read data from there. We have to
# normalize the data we get, which is why we don't simply
# spit out 'Host/OS/ntp'
#
os = get_kb_item("Host/OS/ntp");
if ( os )
{
 set_kb_item(name:"Host/OS/NTP/Fingerprint", value:os);
 processor = get_kb_item("Host/processor/ntp");
 # Normalize intel CPUs 
 if ( processor && ereg(pattern:"i[3-9]86", string:processor)) processor = "i386"; 

 if ("QNX" >< os )
 {
  version = str_replace(find:"QNX", replace:"QNX ", string:os);
  set_kb_item(name:"Host/OS/NTP", value:version);
  set_kb_item(name:"Host/OS/NTP/Confidence", value:90);
  set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
  exit(0);
 }
 if ("sparcv9-wrs-vxworks" >< os )
 { 
   version = "VxWorks";
   set_kb_item(name:"Host/OS/NTP", value:version);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:50);
   set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
   exit(0);
 }
 if ( "Darwin" >< os && "Power Macintosh" >< processor )
 {
   if ( "Darwin/" >< os )
     os -= "Darwin/";
   else
     os -= "Darwin";
   num = split(os, sep:".", keep:FALSE);
   version = "Mac OS X 10." + string(int(num[0]) - 4) + "." + num[1];
   set_kb_item(name:"Host/OS/NTP", value:version);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 if ("OpenVMS AXP" >< os)
 {
   set_kb_item(name:"Host/OS/NTP", value: "OpenVMS");
   set_kb_item(name:"Host/OS/NTP/Confidence", value: 80);
   set_kb_item(name:"Host/OS/NTP/Type", value: "general-purpose");
   exit(0);
 }

 if ( "Darwin" >< os && "i386" >< processor )
 {
   if ( "Darwin/" >< os )
     os -= "Darwin/";
   else
     os -= "Darwin";
   num = split(os, sep:".", keep:FALSE);
   if ( int(num[0]) == 8 && int(num[1]) == 8 && int(num[2]) == 2 )
   {
    version = "AppleTV/3.0";
    set_kb_item(name:"Host/OS/NTP", value:version);
    set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
    set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
   }
   else
   {
    version = "Mac OS X 10." + string(int(num[0]) - 4) + "." + num[1] + " (intel)";
    set_kb_item(name:"Host/OS/NTP", value:version);
    set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
    set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   }
   exit(0);
 }

 if ("UNIX/HPUX" >< os )
 {
   set_kb_item(name:"Host/OS/NTP", value:"HP/UX");
   set_kb_item(name:"Host/OS/NTP/Confidence", value:50);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 if ("NetBSD" >< os )
 {
   os -= "NetBSD";
   version = "NetBSD " + os;
   if ( processor ) version += " (" + processor + ")";

   set_kb_item(name:"Host/OS/NTP", value:version);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 } 

 if ("FreeBSD" >< os )
 {
   os -= "FreeBSD";
   version = "FreeBSD " + os;
   if ( processor ) version += " (" + processor + ")";

   set_kb_item(name:"Host/OS/NTP", value:version);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 if ("WINDOWS/NT" >< os )
 {
   os = "Microsoft Windows";
   set_kb_item(name:"Host/OS/NTP", value:os);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:10);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 if ("OpenBSD" >< os )
 {
   os -= "OpenBSD";
   version = "OpenBSD" + os;
   if ( processor ) version += " (" + processor + ")";

   set_kb_item(name:"Host/OS/NTP", value:version);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 if ("Linux" >< os )
 {
   confidence = 75;
   if ("Linux/" >< os ) os -= "Linux/";
   else os -= "Linux";
   os = "Linux Kernel " + os;
   version = os;
   if ( version =~ "Linux Kernel [0-9]\.[0-9]\.[0-9]" )
	confidence = 95;
   if ( processor ) version += " (" + processor + ")";
   set_kb_item(name:"Host/OS/NTP", value:version);
   set_kb_item(name:"Host/OS/NTP/Confidence", value:95);
   set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
   exit(0);
 }

 if ( "cisco" >< os )
 {
  set_kb_item(name:"Host/OS/NTP", value:"CISCO IOS");
  set_kb_item(name:"Host/OS/NTP/Confidence", value:6);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 if ("SunOS5." >< os )
 {
  os -= "SunOS5.";
  if ( int(os) >= 7 ) os = "Sun Solaris " + os;
  else os = "Sun Solaris 2." + os;
  version = os;
  if ( processor ) version += " (" + processor + ")";
  set_kb_item(name:"Host/OS/NTP", value:version);
  set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 else if ("SunOS/5." >< os )
 {
  os -= "SunOS/5.";
  if ( int(os) >= 7 ) os = "Sun Solaris " + os;
  else os = "Sun Solaris 2." + os;
  version = os;
  if ( processor ) version += " (" + processor + ")";
  set_kb_item(name:"Host/OS/NTP", value:version);
  set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 else if ( os == "SunOS" )
 {
  set_kb_item(name:"Host/OS/NTP", value:"Solaris");
  set_kb_item(name:"Host/OS/NTP/Confidence", value:75);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 if ( "UNIX/AIX" >< os )
 {
  set_kb_item(name:"Host/OS/NTP", value:"AIX");
  set_kb_item(name:"Host/OS/NTP/Confidence", value:75);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 if ( os == "cisco" )
 {
  set_kb_item(name:"Host/OS/NTP", value:"CISCO IOS");
  set_kb_item(name:"Host/OS/NTP/Confidence", value:10);
  set_kb_item(name:"Host/OS/NTP/Type", value:"router");
  exit(0);
 }
 if ( os =~ "^OSF1V[0-9.]*$" )
 {
  os -= "OSF1V";
  set_kb_item(name:"Host/OS/NTP", value:"Tru64 Unix version " + os);
  set_kb_item(name:"Host/OS/NTP/Confidence", value:98);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 if ( os == "SCO_SV" )
 {
  set_kb_item(name:"Host/OS/NTP", value:"SCO OpenServer");
  set_kb_item(name:"Host/OS/NTP/Confidence", value:75);
  set_kb_item(name:"Host/OS/NTP/Type", value:"general-purpose");
  exit(0);
 }
 if ( os =~ "JUNOS[0-9]." )
 {
  set_kb_item(name:"Host/OS/NTP", value:"Juniper Router");
  set_kb_item(name:"Host/OS/NTP/Confidence", value:76);
  set_kb_item(name:"Host/OS/NTP/Type", value:"embedded");
  exit(0);
 }

 v = eregmatch(string: os, pattern: "^VMkernel/([0-9][0-9.]+)$");
 if (! isnull(v))
 {
  set_kb_item(name:"Host/OS/NTP", value: "VMware ESX "+v[1]);
  set_kb_item(name:"Host/OS/NTP/Confidence", value:90);
  set_kb_item(name:"Host/OS/NTP/Type", value:"hypervisor");
  exit(0);
 }
}
