#
# (C) Tenable Network Security, Inc.
#


if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(30255);
 script_version ("$Revision: 1.6 $");

 if (NASL_LEVEL >= 3000)
  {
    script_cve_id("CVE-2007-0355", "CVE-2007-4568", "CVE-2007-6015", "CVE-2008-0035", "CVE-2008-0037",
                  "CVE-2008-0038", "CVE-2008-0039", "CVE-2008-0040", "CVE-2008-0041", "CVE-2008-0042");
    script_bugtraq_id(22101, 25898, 26791, 27296);
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

 script_name(english:"Mac OS X < 10.5.2 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5 that
is older than version 10.5.2.

Mac OS X 10.5.2 contains several security fixes for a number 
of programs." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307430" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Feb/msg00002.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/13987" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.5.2" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 
script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("Host/OS");
if ( ! os ) exit(0);
if ( ereg(pattern:"Mac OS X 10\.5\.[01]([^0-9]|$)", string:os)) security_hole(0);
