#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);



include("compat.inc");

if (description)
{
  script_id(29723);
  script_version ("$Revision: 1.15 $");

  script_cve_id("CVE-2006-0024", "CVE-2007-1218", "CVE-2007-1659", "CVE-2007-1660", "CVE-2007-1661",
                "CVE-2007-1662", "CVE-2007-3798", "CVE-2007-3876", "CVE-2007-4131", "CVE-2007-4351",
                "CVE-2007-4572", "CVE-2007-4708", "CVE-2007-4709", "CVE-2007-4710", "CVE-2007-4766",
                "CVE-2007-4767", "CVE-2007-4768", "CVE-2007-4965", "CVE-2007-5116", "CVE-2007-5379",
                "CVE-2007-5380", "CVE-2007-5398", "CVE-2007-5476", "CVE-2007-5770", "CVE-2007-5847",
                "CVE-2007-5848", "CVE-2007-5849", "CVE-2007-5850", "CVE-2007-5851", "CVE-2007-5853",
                "CVE-2007-5854", "CVE-2007-5855", "CVE-2007-5856", "CVE-2007-5857", "CVE-2007-5858",
                "CVE-2007-5859", "CVE-2007-5860", "CVE-2007-5861", "CVE-2007-5863", "CVE-2007-6077",
                "CVE-2007-6165");
  script_bugtraq_id(17106, 22772, 24965, 25417, 25696, 26096, 26268, 26274, 26346,
                    26350, 26421, 26454, 26455, 26510, 26598, 26908, 26910, 26926);
  script_xref(name:"OSVDB", value:"23908");
  script_xref(name:"OSVDB", value:"32427");
  script_xref(name:"OSVDB", value:"38128");
  script_xref(name:"OSVDB", value:"38183");
  script_xref(name:"OSVDB", value:"38213");
  script_xref(name:"OSVDB", value:"39179");
  script_xref(name:"OSVDB", value:"39180");
  script_xref(name:"OSVDB", value:"39193");
  script_xref(name:"OSVDB", value:"40142");
  script_xref(name:"OSVDB", value:"40409");
  script_xref(name:"OSVDB", value:"40717");
  script_xref(name:"OSVDB", value:"40718");
  script_xref(name:"OSVDB", value:"40719");
  script_xref(name:"OSVDB", value:"40720");
  script_xref(name:"OSVDB", value:"40721");
  script_xref(name:"OSVDB", value:"40722");
  script_xref(name:"OSVDB", value:"40724");
  script_xref(name:"OSVDB", value:"40725");
  script_xref(name:"OSVDB", value:"40726");
  script_xref(name:"OSVDB", value:"40727");
  script_xref(name:"OSVDB", value:"40728");
  script_xref(name:"OSVDB", value:"40729");
  script_xref(name:"OSVDB", value:"40730");
  script_xref(name:"OSVDB", value:"40731");
  script_xref(name:"OSVDB", value:"40732");
  script_xref(name:"OSVDB", value:"40733");
  script_xref(name:"OSVDB", value:"40734");
  script_xref(name:"OSVDB", value:"40735");
  script_xref(name:"OSVDB", value:"40736");
  script_xref(name:"OSVDB", value:"40737");
  script_xref(name:"OSVDB", value:"40738");
  script_xref(name:"OSVDB", value:"40759");
  script_xref(name:"OSVDB", value:"40760");
  script_xref(name:"OSVDB", value:"40766");
  script_xref(name:"OSVDB", value:"40875");
  script_xref(name:"OSVDB", value:"42028");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2007-009)");
  script_summary(english:"Check for the presence of Security Update 2007-009");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5 or 10.4 that
does not have the security update 2007-009 applied. 

This update contains several security fixes for a large number of
programs." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307179" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2007/Dec/msg00002.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/13649" );
 script_set_attribute(attribute:"solution", value:
"Install Security Update 2007-009 :

http://www.apple.com/support/downloads/securityupdate200700910411universal.html
http://www.apple.com/support/downloads/securityupdate200700910411ppc.html
http://www.apple.com/support/downloads/securityupdate20070091051.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");
  exit(0);
}






uname = get_kb_item("Host/uname");
if ( ! uname ) exit(0);
if ( egrep(pattern:"Darwin.* (8\.[0-9]\.|8\.1[01]\.)", string:uname) )
{
  packages = get_kb_item("Host/MacOSX/packages");
  if ( ! packages ) exit(0);
  if (!egrep(pattern:"^SecUpd(Srvr)?(2007-009|200[89]-|20[1-9][0-9]-)", string:packages)) 
    security_hole(0);
}
else if ( egrep(pattern:"Darwin.* (9\.[01]\.)", string:uname) )
{
 packages = get_kb_item("Host/MacOSX/packages/boms");
 if ( ! packages ) exit(0);
 if ( !egrep(pattern:"^com\.apple\.pkg\.update\.security\.2007\.009\.bom", string:packages) )
	security_hole(0);
}
