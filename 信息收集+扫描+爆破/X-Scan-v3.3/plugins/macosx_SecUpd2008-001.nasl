#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);



include("compat.inc");

if (description)
{
  script_id(30254);
  script_version ("$Revision: 1.16 $");

  if (NASL_LEVEL >= 3000)
  {
    script_cve_id("CVE-2007-0355", "CVE-2007-4568", "CVE-2007-6015", "CVE-2008-0035", "CVE-2008-0037",
                  "CVE-2008-0038", "CVE-2008-0039", "CVE-2008-0040", "CVE-2008-0041", "CVE-2008-0042");
    script_bugtraq_id(22101, 25898, 26791, 27296, 27736);
    script_xref(name:"milw0rm", value:"3151");
    script_xref(name:"OSVDB", value:"32693");
    script_xref(name:"OSVDB", value:"37721");
    script_xref(name:"OSVDB", value:"39191");
    script_xref(name:"OSVDB", value:"40891");
    script_xref(name:"OSVDB", value:"41503");
    script_xref(name:"OSVDB", value:"41504");
    script_xref(name:"OSVDB", value:"41505");
    script_xref(name:"OSVDB", value:"41506");
    script_xref(name:"OSVDB", value:"41507");
    script_xref(name:"OSVDB", value:"41508");
  }

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2008-001)");
  script_summary(english:"Check for the presence of Security Update 2008-001");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not
have the security update 2008-001 applied. 

This update contains several security fixes for a number of programs." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307430" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Feb/msg00002.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/13987" );
 script_set_attribute(attribute:"solution", value:
"Install Security Update 2008-001 or later." );
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

  if (!egrep(pattern:"^SecUpd(Srvr)?(2008-00[1-8]|2009-|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
