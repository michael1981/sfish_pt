#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);



include("compat.inc");

if (description)
{
  script_id(34374);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2007-2691", "CVE-2007-4850", "CVE-2007-5333", "CVE-2007-5342", "CVE-2007-5461",
                "CVE-2007-5969", "CVE-2007-6286", "CVE-2007-6420", "CVE-2008-0002", "CVE-2008-0226",
                "CVE-2008-0227", "CVE-2008-0674", "CVE-2008-1232", "CVE-2008-1389", "CVE-2008-1678",
                "CVE-2008-1767", "CVE-2008-1947", "CVE-2008-2079", "CVE-2008-2364", "CVE-2008-2370",
                "CVE-2008-2371", "CVE-2008-2712", "CVE-2008-2938", "CVE-2008-3294", "CVE-2008-3432",
                "CVE-2008-3641", "CVE-2008-3642", "CVE-2008-3643", "CVE-2008-3645", "CVE-2008-3646",
                "CVE-2008-3647", "CVE-2008-3912", "CVE-2008-3913", "CVE-2008-3914", "CVE-2008-4101",
                "CVE-2008-4211", "CVE-2008-4212", "CVE-2008-4214", "CVE-2008-4215");
  script_bugtraq_id(24016, 26070, 26765, 27006, 27140, 27236, 27413, 27703,
                    27706, 27786, 29106, 29312, 29502, 29653, 29715, 30087,
                    30279, 30494, 30496, 30633, 30795, 30994, 31051, 31692,
                    31707, 31708, 31711, 31715, 31716, 31718, 31719, 31720,
                    31721, 31722);
  script_xref(name:"OSVDB", value:"38187");
  script_xref(name:"OSVDB", value:"39833");
  script_xref(name:"OSVDB", value:"41435");
  script_xref(name:"OSVDB", value:"41989");
  script_xref(name:"OSVDB", value:"42608");
  script_xref(name:"OSVDB", value:"42937");
  script_xref(name:"OSVDB", value:"43219");
  script_xref(name:"OSVDB", value:"45419");
  script_xref(name:"OSVDB", value:"46085");
  script_xref(name:"OSVDB", value:"46306");
  script_xref(name:"OSVDB", value:"47462");
  script_xref(name:"OSVDB", value:"47463");
  script_xref(name:"OSVDB", value:"47881");
  script_xref(name:"OSVDB", value:"48237");
  script_xref(name:"OSVDB", value:"48238");
  script_xref(name:"OSVDB", value:"48239");
  script_xref(name:"OSVDB", value:"48968");
  script_xref(name:"OSVDB", value:"48969");
  script_xref(name:"OSVDB", value:"48970");
  script_xref(name:"OSVDB", value:"48973");
  script_xref(name:"OSVDB", value:"48974");
  script_xref(name:"OSVDB", value:"48980");
  script_xref(name:"OSVDB", value:"48986");
  script_xref(name:"OSVDB", value:"48987");
  script_xref(name:"OSVDB", value:"48988");
  script_xref(name:"OSVDB", value:"51435");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2008-007)");
  script_summary(english:"Check for the presence of Security Update 2008-007");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5 or 10.4 that
does not have the security update 2008-007 applied. 

This security update contains fixes for the following products :

  - Apache
  - Certificates
  - ClamAV
  - ColorSync
  - CUPS
  - Finder
  - launchd
  - libxslt
  - MySQL Server
  - Networking
  - PHP
  - Postfix
  - PSNormalizer
  - QuickLook
  - rlogin
  - Script Editor
  - Single Sign-On
  - Tomcat
  - vim
  - Weblog" );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3216" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Oct/msg00001.html" );
 script_set_attribute(attribute:"solution", value:
"Install Security Update 2008-007 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");
  exit(0);
}


uname = get_kb_item("Host/uname");
if (!uname) exit(0);

if (egrep(pattern:"Darwin.* (8\.[0-9]\.|8\.1[01]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages");
  if (!packages) exit(0);

  if (!egrep(pattern:"^SecUpd(Srvr)?(2008-00[78]|2009-|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
else if (egrep(pattern:"Darwin.* (9\.[0-5]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(0);

  if (!egrep(pattern:"^com\.apple\.pkg\.update\.security\.2008\.007\.bom", string:packages))
    security_hole(0);
}

