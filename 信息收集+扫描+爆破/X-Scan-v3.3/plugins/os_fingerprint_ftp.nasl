#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35658);
  script_version("$Revision: 1.5 $");

  script_name(english: "OS Identification : FTP");

  script_set_attribute(attribute:"synopsis", value: "The remote FTP banner reveals the running operating system.");
  script_set_attribute(attribute:"description", value:
"The remote operating system can be guessed by looking at the FTP banner.");
  script_set_attribute(attribute:"risk_factor", value: "None");
  script_set_attribute(attribute:"solution", value: "None");
  script_end_attributes();

  script_summary(english: "Deduces the remote operating system from the FTP banner");
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_family(english: "General");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

function test(banner)
{
# 220 X.Y.COM MultiNet FTP Server Process V4.4(16) at Thu 20-Nov-2008 8:24AM-PST
if ("MultiNet FTP Server Process" >< banner)
{
 set_kb_item(name:"Host/OS/FTP", value:"OpenVMS");
 set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/FTP/Confidence", value: 50);
 exit(0);
}

# 220 P-660RU-T FTP version 1.0 ready at Sat Feb 05 19:17:46 2000 
if ("P-660RU-T FTP version " >< banner)
{
 set_kb_item(name:"Host/OS/FTP", value:"ZyXEL Prestige 660RU-T ADSL Router");
 set_kb_item(name:"Host/OS/FTP/Type", value:"router");
 set_kb_item(name:"Host/OS/FTP/Confidence", value: 76);
 exit(0);
}

if (egrep(string: banner, pattern: "FTP server \(Version [0-9]+\(PHNE_[0-9]+\) "))
{
  set_kb_item(name:"Host/OS/FTP", value:"HP/UX");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 50);
  exit(0);
}

if (" Microsoft FTP Service (Version 4.0)." >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: "Microsoft Windows NT 4.0");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 60);
  exit(0);
}


if (" Microsoft FTP Service (Version 5.0)." >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: "Microsoft Windows 2000");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 60);
  exit(0);
}

if ("Microsoft FTP Service" >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value:"Microsoft Windows Server 2003");
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 50);
  exit(0);
}

if (" FTP server (Version 6.4/OpenBSD) ready." >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: 'OpenBSD 2.6\nOpenBSD 2.7');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

if (" FTP server (Version 6.5/OpenBSD) ready." >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: 'OpenBSD 2.8\nOpenBSD 2.9\nOpenBSD 3.0\nOpenBSD 3.1\nOpenBSD 3.2\nOpenBSD 3.3\nOpenBSD 3.4\nOpenBSD 3.5\nOpenBSD 3.6');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

if (" FTP server (Version 6.6/OpenBSD) ready." >< banner)
{
# OpenBSD 4.2 or 4.3 say: FTP server ready.
  set_kb_item(name:"Host/OS/FTP", value: 'OpenBSD 3.7\nOpenBSD 3.8\nOpenBSD 3.9\nOpenBSD 4.0\nOpenBSD 4.1');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

if (" FTP server (NetBSD-ftpd 20050303) " >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: 'NetBSD 3.0.2\nNetBSD 3.1');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}

if (" FTP server (NetBSD-ftpd 20060923nb4) " >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: 'NetBSD 4.0.1');
  set_kb_item(name:"Host/OS/FTP/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 55);
  exit(0);
}
if (" FTP server (EMC-SNAS: " >< banner)
{
  set_kb_item(name:"Host/OS/FTP", value: 'EMC Celerra File Server');
  set_kb_item(name:"Host/OS/FTP/Type", value:"embedded");
  set_kb_item(name:"Host/OS/FTP/Confidence", value: 95);
  exit(0);
}
}

ports_l = make_service_list(21, "Services/ftp");

foreach port (ports_l)
{
  banner = get_ftp_banner(port: port);
  if (strlen(banner) > 0 && banner =~ "^[1-5][0-9][0-9][ -]")
    test(banner: banner);
}

