#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if ( NASL_LEVEL < 3004 ) exit(0);



include("compat.inc");

if (description)
{
  script_id(32478);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-3352", "CVE-2005-3357", "CVE-2006-3747", "CVE-2007-0071", "CVE-2007-1863",
                "CVE-2007-3847", "CVE-2007-4465", "CVE-2007-5000", "CVE-2007-5266", "CVE-2007-5268",
                "CVE-2007-5269", "CVE-2007-5275", "CVE-2007-6019", "CVE-2007-6359", "CVE-2007-6388",
                "CVE-2007-6612", "CVE-2008-0177", "CVE-2008-1027", "CVE-2008-1028", "CVE-2008-1030",
                "CVE-2008-1031", "CVE-2008-1032", "CVE-2008-1033", "CVE-2008-1034", "CVE-2008-1035",
                "CVE-2008-1036", "CVE-2008-1571", "CVE-2008-1572", "CVE-2008-1573", "CVE-2008-1574",
                "CVE-2008-1575", "CVE-2008-1576", "CVE-2008-1577", "CVE-2008-1578", "CVE-2008-1579",
                "CVE-2008-1580", "CVE-2008-1654", "CVE-2008-1655");
  script_bugtraq_id("15834", "25489", "25957", "26840", "26930", "27133", "27642", "28694", "29480",
                    "29481", "29483", "29484", "29486", "29487", "29488", "29489", "29490", "29491",
                    "29492", "29493", "29500", "29501", "29511", "29513", "29514", "29520", "29521");
  script_xref(name:"OSVDB", value:"21705");
  script_xref(name:"OSVDB", value:"37051");
  script_xref(name:"OSVDB", value:"40694");
  script_xref(name:"OSVDB", value:"41111");
  script_xref(name:"OSVDB", value:"41489");
  script_xref(name:"OSVDB", value:"43979");
  script_xref(name:"OSVDB", value:"45690");
  script_xref(name:"OSVDB", value:"45694");
  script_xref(name:"OSVDB", value:"45695");
  script_xref(name:"OSVDB", value:"45696");
  script_xref(name:"OSVDB", value:"45697");
  script_xref(name:"OSVDB", value:"45698");
  script_xref(name:"OSVDB", value:"45699");
  script_xref(name:"OSVDB", value:"45700");
  script_xref(name:"OSVDB", value:"45701");
  script_xref(name:"OSVDB", value:"45702");
  script_xref(name:"OSVDB", value:"45703");
  script_xref(name:"OSVDB", value:"45704");
  script_xref(name:"OSVDB", value:"45705");
  script_xref(name:"OSVDB", value:"45706");
  script_xref(name:"OSVDB", value:"45707");
  script_xref(name:"OSVDB", value:"45708");
  script_xref(name:"OSVDB", value:"45709");
  script_xref(name:"OSVDB", value:"45710");
  script_xref(name:"OSVDB", value:"45711");
  script_xref(name:"Secunia", value:"30430");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2008-003)");
  script_summary(english:"Check for the presence of Security Update 2008-003");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not
have the security update 2008-003 applied. 

This update contains security fixes for a number of programs." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1897" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/May/msg00001.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/14755" );
 script_set_attribute(attribute:"solution", value:
"Install Security Update 2008-003 or later." );
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

  if (!egrep(pattern:"^SecUpd(Srvr)?(2008-00[3-8]|2009-|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
