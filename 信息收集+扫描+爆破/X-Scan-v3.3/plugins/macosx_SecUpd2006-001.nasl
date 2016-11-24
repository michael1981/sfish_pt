#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");

if(description)
{
 script_id(20990);
 script_version ("$Revision: 1.13 $");

 script_cve_id("CVE-2005-2713", "CVE-2005-2714", "CVE-2005-3319", "CVE-2005-3353", "CVE-2005-3391",
               "CVE-2005-3392", "CVE-2005-3706", "CVE-2005-3712", "CVE-2005-4217", "CVE-2005-4504",
               "CVE-2006-0383", "CVE-2006-0384", "CVE-2006-0386", "CVE-2006-0387", "CVE-2006-0388",
               "CVE-2006-0389", "CVE-2006-0391", "CVE-2006-0395", "CVE-2006-0848");
 script_bugtraq_id(16736, 16907);
 script_xref(name:"OSVDB", value:"22037");
 script_xref(name:"OSVDB", value:"23510");
 script_xref(name:"OSVDB", value:"23636");
 script_xref(name:"OSVDB", value:"23637");
 script_xref(name:"OSVDB", value:"23638");
 script_xref(name:"OSVDB", value:"23640");
 script_xref(name:"OSVDB", value:"23641");
 script_xref(name:"OSVDB", value:"23642");
 script_xref(name:"OSVDB", value:"23643");
 script_xref(name:"OSVDB", value:"23644");
 script_xref(name:"OSVDB", value:"23645");
 script_xref(name:"OSVDB", value:"23646");
 script_xref(name:"OSVDB", value:"23647");
 script_xref(name:"OSVDB", value:"23648");
 script_xref(name:"OSVDB", value:"23649");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2006-001)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote operating system is missing a vendor supplied patch." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Apple Mac OS X, but lacks 
Security Update 2006-001. 

This security update contains fixes for the following
applications :

apache_mod_php
automount
Bom
Directory Services
iChat
IPSec
LaunchServices
LibSystem
loginwindow
Mail
rsync
Safari
Syndication" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=303382" );
 script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 :
http://www.apple.com/support/downloads/securityupdate2006001macosx1045ppc.html
http://www.apple.com/support/downloads/securityupdate2006001macosx1045intel.html

Mac OS X 10.3 :
http://www.apple.com/support/downloads/securityupdate20060011039client.html
http://www.apple.com/support/downloads/securityupdate20060011039server.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 script_summary(english:"Check for Security Update 2006-001");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-5]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2006-00[123467]|2007-003)", string:packages)) security_hole(0);
}
