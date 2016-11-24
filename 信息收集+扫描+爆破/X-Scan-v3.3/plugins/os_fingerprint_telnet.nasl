#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29831);
  script_version("$Revision: 1.17 $");

  script_name(english:"OS Identification : Telnet");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based
on the telnet banner." );
 script_set_attribute(attribute:"description", value:
"This script attempts to identify the operating system type and 
version by looking at the data returned by the remote telnet 
banner." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
  script_summary(english:"Determines the remote operating system");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_family(english:"General");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_keys("Services/telnet/banner/23");
 
  exit(0);
}


include("telnet_func.inc");
banner = get_telnet_banner(port:23);
if ( ! banner ) exit(0);
confidence = 51;
if ( "SunOS 5" >< banner )
{
 line = egrep(pattern:"SunOS 5\.[0-9]", string:banner);
 if ( line && line != banner )
 {
  version = ereg_replace(pattern:"SunOS 5\.([0-9]+).*", string:line, replace:"\1");
  if (  int(version) ) {
	set_kb_item(name:"Host/OS/telnet", value:"Sun Solaris " + int(version));
	set_kb_item(name:"Host/OS/telnet/Confidence", value:confidence);
	set_kb_item(name:"Host/OS/telnet/Type", value:"general-purpose");
	}
 }
 exit(0);
}
# eg,
#   SCO OpenServer(TM) Release 5 (example.com) (ttyp4)
if ("SCO OpenServer(TM) Release" >< banner)
{
  set_kb_item(name:"Host/OS/telnet", value:"SCO OpenServer");
  set_kb_item(name:"Host/OS/telnet/Confidence", value:confidence);
  set_kb_item(name:"Host/OS/telnet/Type", value:"general-purpose");
  exit(0);
}
if (egrep(pattern:"Serial Number .* MAC address", string:banner) &&
 	 "Software version " >< banner &&
	 "Press Enter to go into Setup Mode, wait to close" >< banner )
{
	set_kb_item(name:"Host/OS/telnet", value:"Modbus/TCP to RTU Bridge");
	set_kb_item(name:"Host/OS/telnet/Confidence", value:98);
	set_kb_item(name:"Host/OS/telnet/Type", value:"embedded");
	exit(0);
}

v = eregmatch(string: chomp(banner), pattern: "^(Linux )?Kernel ([12]\.[0-6](\.[0-9A-Za-z.-]+))");
if (! isnull(v)) linux_kernel = "Linux Kernel "+v[2];

if ("Ubuntu " >< banner)
{
# Ubuntu 8.04.1
# ubuntu login: 
 line = egrep(string: banner, 
 pattern: "^Ubuntu ([4-9]|1[0-9])\.([1-9]|1[0-2])(\.[0-9])? *$" );
 if (strlen(line) > 0)
 {
   if (! linux_kernel) linux_kernel = "Linux Kernel 2.6";
   set_kb_item(name:"Host/OS/telnet", 
   		value: linux_kernel + " on "+ chomp(line));
   set_kb_item(name:"Host/OS/telnet/Confidence", value:confidence);
   set_kb_item(name:"Host/OS/telnet/Type", value:"general-purpose");
 }
 exit(0);
}

if ("CentOS " >< banner)
{
# CentOS release 4.6 (Final)
# Kernel 2.6.9-67.0.15.EL on an i686
 line = egrep(string: banner, pattern: "^CentOS release [1-5]\.[0-9] " );
 if (strlen(line) > 0)
 {
   line = chomp(line);
   if (! linux_kernel)
     if (line =~ "^CentOS release [23]\.") linux_kernel = "Linux Kernel 2.4";
   else if (line =~ "^CentOS release [45]\.") linux_kernel = "Linux Kernel 2.6";
   else linux_kernel = "Linux Kernel 2.6"; # Unrecognized distro?
   set_kb_item(name:"Host/OS/telnet", 
   		value: linux_kernel + " on "+ line);
   set_kb_item(name:"Host/OS/telnet/Confidence", value:confidence);
   set_kb_item(name:"Host/OS/telnet/Type", value:"general-purpose");
 }
 exit(0);
}

if ("Fedora " >< banner)
{
# Fedora release 8 (Werewolf)
# Kernel 2.6.25.4-10.fc8 on an i686
# login: 
 line = egrep(string: banner, pattern: "^Fedora (Core )? release [1-9] " );
 if (strlen(line) > 0)
 {
   line = chomp(line);
   if (! linux_kernel)
     if (line =~ "^Fedora (Core )? release 1 ") linux_kernel = "Linux Kernel 2.4";
     else linux_kernel = "Linux Kernel 2.6";
   set_kb_item(name:"Host/OS/telnet", 
   		value: linux_kernel + " on "+ line);
   set_kb_item(name:"Host/OS/telnet/Confidence", value:confidence);
   set_kb_item(name:"Host/OS/telnet/Type", value:"general-purpose");
 }
 exit(0);
}

if ("Red Hat Entreprise Linux " >< banner)
{
# Red Hat Enterprise Linux ES release 3 (Taroon Update 9)
# Kernel 2.4.21-57.EL on an i686
#
# Red Hat Enterprise Linux Server release 5.2 (Tikanga)
# Kernel 2.6.18-92.1.6.el5 on an i686
 line = egrep(string: banner, pattern: "^Red Hat Enterprise Linux [A-Za-z]+ release [0-9.]+ " );
 if (strlen(line) > 0)
 {
   line = chomp(line);
   if (! linux_kernel)
     if (line =~ " release 3 ") linux_kernel = "Linux Kernel 2.4";
     else linux_kernel = "Linux Kernel 2.6";
   set_kb_item(name:"Host/OS/telnet", 
   		value: linux_kernel + " on "+ line);
   set_kb_item(name:"Host/OS/telnet/Confidence", value:confidence);
   set_kb_item(name:"Host/OS/telnet/Type", value:"general-purpose");
 }
 exit(0);
}

if ("Red Hat Linux " >< banner)
{
# Red Hat Linux release 4.2 (Biltmore)
# Kernel 2.0.30 on an i686
 line = egrep(string: banner, pattern: "^Red Hat Linux release [0-9.]+ " );
 if (strlen(line) > 0)
 {
   line = chomp(line);
   if (! linux_kernel)
     if (line =~ " release (4\.2|5\.[0-2])") linux_kernel = "Linux Kernel 2.0";
     else if (line =~ " release (6\.[0-2]|7\.0)") linux_kernel = "Linux Kernel 2.2";
     else linux_kernel = "Linux Kernel 2.4";
   set_kb_item(name:"Host/OS/telnet", 
   		value: linux_kernel + " on "+ line);
   set_kb_item(name:"Host/OS/telnet/Confidence", value:confidence);
   set_kb_item(name:"Host/OS/telnet/Type", value:"general-purpose");
 }
 exit(0);
}

if ("Linux Mandrake" >< banner)
{
# Linux Mandrake release 5.2 (Leelo)
# Linux Mandrake release 7.0 (Air)
  line = egrep(string: banner, pattern: "^Linux Mandrake release [5-9]\.[0-9]+ ");
  if (strlen(line) > 0)
  {
    version = ereg_replace( string: chomp(line),
    	      		    pattern: "^Linux Mandrake release ([5-9]\.[0-9]+) ",
			    replace: "MDK\1" );
    if (! linux_kernel)
      if (version =~ "^MDK5") linux_kernel = "Linux Kernel 2.0";
      else if (version =~ "^MDK[67]") linux_kernel = "Linux Kernel 2.2";
      else if (version =~ "^MDK[89]") linux_kernel = "Linux Kernel 2.4";
      else if (version =~ "^MDK10") linux_kernel = "Linux Kernel 2.6";
      else if (version =~ "^MDK200[6-8]") linux_kernel = "Linux Kernel 2.6";
      else linux_kernel = "Linux Kernel 2.6";
    set_kb_item(name:"Host/OS/telnet", value: linux_kernel + " on " + version);
    set_kb_item(name:"Host/OS/telnet/Confidence", value:confidence);
    set_kb_item(name:"Host/OS/telnet/Type", value:"general-purpose");
  }
  exit(0);
}

if ("Debian" >< banner)
{
# Debian GNU/Linux 4.0
# Debian GNU/Linux 2.2 
  line = egrep(string: banner, pattern: "^Debian GNU/Linux [1-9]\.[0-9]");
  if (strlen(line) > 0)
  {
    version = chomp(line) - "Debian GNU/Linux ";
    if (! linux_kernel)
      if (version =~ "^(1\.|2\.[01])") linux_kernel = "Linux Kernel 2.0";
      else if (version == "2.2" || version == "3.0") linux_kernel = "Linux Kernel 2.2";
      else if (version == "3.1") linux_kernel = "Linux Kernel 2.4";
      else linux_kernel = "Linux Kernel 2.6";
    set_kb_item(name:"Host/OS/telnet", value: linux_kernel + " on Debian " + version);
    set_kb_item(name:"Host/OS/telnet/Confidence", value:confidence);
    set_kb_item(name:"Host/OS/telnet/Type", value:"general-purpose");
  }
  exit(0);
}

if ("SUSE" >< banner || "SuSE" >< banner)
{
# Welcome to openSUSE 11.0 (X86-64) - Kernel 2.6.25.11-0.1-default (15).
# No usable remote banner for very old SuSE - /etc/issue contains:
# Welcome to S.u.S.E. Linux 5.1 - Kernel \r (\l)
#
# Welcome to SUSE Linux Enterprise Desktop 10 SP2 (i586) - Kernel %r (%t).
# Welcome to SUSE Linux Enterprise Server 10 SP1 (i586) - Kernel 2.6.16.46-0.12-default (1).
#
# Welcome to SuSE Linux 9.3 (i586) - Kernel %r (%t).
# Welcome to SuSE Linux 9.3 (i586) - Kernel 2.6.11.4-21.10-default (2).

  line = egrep(string: banner, pattern: "^Welcome to (open)?S[uU]SE ([A-Z][a-z]+ )*[0-9.]+ .*\(.*\) - Kernel [0-9]");
  v = NULL;
  if (strlen(line) > 0)
    v = eregmatch(string: line, pattern: " (open)?S[uU]SE ([A-Z][a-z]+ )*([0-9.]+) ");
  if (! isnull(v))
  {
    version = v[3];
    if (! linux_kernel)
      if (version =~ "^(9\.0|8\.|7\.[23])") linux_kernel = "Linux Kernel 2.4";
      else if (version =~ "^(7\.[01]|6[1-4])") linux_kernel = "Linux Kernel 2.2";
      else if (version =~ "^(6\.0|5\.)") linux_kernel = "Linux Kernel 2.0";
      else if (version =~ "^(9\.[1-3]|1[01])") linux_kernel = "Linux Kernel 2.6";
      else linux_kernel = "Linux Kernel 2.6";
    set_kb_item(name:"Host/OS/telnet", value: linux_kernel + " on SuSE " + version);
    set_kb_item(name:"Host/OS/telnet/Confidence", value:confidence);
    set_kb_item(name:"Host/OS/telnet/Type", value:"general-purpose");
  }
  exit(0);
}

if (egrep (string: banner, pattern: "^Corel Linux/"))
{
# Corel Linux/Linux CorelLinux.localdomain
  if (! linux_kernel) linux_kernel = "Linux Kernel 2.2";
  set_kb_item(name:"Host/OS/telnet", value: linux_kernel + " on Corel Linux");
  set_kb_item(name:"Host/OS/telnet/Confidence", value:confidence);
  set_kb_item(name:"Host/OS/telnet/Type", value:"general-purpose");
  exit(0);
}

if ("Caldera OpenLinux(TM)" >< banner)
{
# Caldera OpenLinux(TM)
# Version 2.3
# Copyright 1996-1999 Caldera Systems, Inc.
  version = egrep(string: banner, "^Version +[12]\.[0-9]+");
  if (! linux_kernel) linux_kernel = "Linux Kernel 2.2"; # Not sure but who cares? This distro has been defunct for many years
  if (strlen(version) > 0)
  {
    version = ereg_replace(string: version, replace: "\1",
    	      pattern: "^Version +([12]\.[0-9]+)");
    set_kb_item(name:"Host/OS/telnet", value: "OpenLinux " + version);
  }
  else
    set_kb_item(name:"Host/OS/telnet", value: "OpenLinux");
  set_kb_item(name:"Host/OS/telnet/Confidence", value:confidence);
  set_kb_item(name:"Host/OS/telnet/Type", value:"general-purpose");
  exit(0);
}
# No /etc/issue.net on Slackware 7.0 by default
# No /etc/issue or issue.net on IcePack 2.75; no usable uname either
#
# TurboLinux release 6.0 English Server (Coyote)
# Kernel 2.2.13-12smp on an i686 (.localdomain)
# TTY: 0
#
# Red Flag Linux release 3.2
# (same thing in /etc/redflag-release)
#
# $ more /etc/turbolinux-release 
# release 6.0 English Server (Coyote)
# $ uname -a
# Linux .localdomain 2.2.13-12smp #1 SMP Fri Dec 10 00:10:19 PST 1999 i686 unknown
# $ 
# 
# /etc/issue.net is empty on Slackware 12.1

if ("MikroTik v" >< banner)
{
# MikroTik v3.2
# Login:
 line = egrep(string: banner, pattern:"^MikroTik v[0-9][0-9.]+");
 if (line && line != banner)
 {
   version = ereg_replace(pattern:"^MikroTik v([0-9][0-9.]+).*", replace:"\1", string:line);
   set_kb_item(name:"Host/OS/telnet", value:"MikroTik RouterOS v"+version);
   set_kb_item(name:"Host/OS/telnet/Confidence", value:confidence);
   set_kb_item(name:"Host/OS/telnet/Type", value:"router");
 }
 exit(0);
}

if ("BCM96338 ADSL Router" >< banner)
{
  set_kb_item(name:"Host/OS/telnet", value:"BCM96338 ADSL Router");
  set_kb_item(name:"Host/OS/telnet/Confidence", value: 90);
  set_kb_item(name:"Host/OS/telnet/Type", value:"router");
  exit(0);
}

if (
  "Hewlett-Packard Co. All Rights Reserved." >< banner &&
  egrep(pattern:"ProCurve [^ ]+ Switch", string:banner)
)
{
  set_kb_item(name:"Host/OS/telnet", value:"HP ProCurve Switch");
  set_kb_item(name:"Host/OS/telnet/Confidence", value:90);
  set_kb_item(name:"Host/OS/telnet/Type", value:"switch");
  exit(0);
}
