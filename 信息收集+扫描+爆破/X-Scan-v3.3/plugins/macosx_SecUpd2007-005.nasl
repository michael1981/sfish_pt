#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");

if(description)
{
 script_id(25297);
 script_version ("$Revision: 1.7 $");

 script_cve_id("CVE-2005-3011", "CVE-2006-4095", "CVE-2006-4096", "CVE-2006-4573", "CVE-2006-5467",
               "CVE-2006-6303", "CVE-2007-0493", "CVE-2007-0494", "CVE-2007-0740", "CVE-2007-0750",
               "CVE-2007-0751", "CVE-2007-0752", "CVE-2007-0753", "CVE-2007-1536", "CVE-2007-1558",
               "CVE-2007-2386", "CVE-2007-2390");
 script_bugtraq_id(24144, 24159);
 script_xref(name:"OSVDB", value:"19409");
 script_xref(name:"OSVDB", value:"28557");
 script_xref(name:"OSVDB", value:"28558");
 script_xref(name:"OSVDB", value:"29905");
 script_xref(name:"OSVDB", value:"31922");
 script_xref(name:"OSVDB", value:"31923");
 script_xref(name:"OSVDB", value:"34237");
 script_xref(name:"OSVDB", value:"34238");
 script_xref(name:"OSVDB", value:"34285");
 script_xref(name:"OSVDB", value:"34856");
 script_xref(name:"OSVDB", value:"35141");
 script_xref(name:"OSVDB", value:"35142");
 script_xref(name:"OSVDB", value:"35143");
 script_xref(name:"OSVDB", value:"35144");
 script_xref(name:"OSVDB", value:"35145");
 script_xref(name:"OSVDB", value:"35146");
 script_xref(name:"OSVDB", value:"35147");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2007-005)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes several
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 or 10.3 that
does not have Security Update 2007-005 applied. 

This update fixes security flaws in the following applications :

Alias Manager
BIND
CoreGraphics
crontabs
fetchmail
file
iChat
mDNSResponder
PPP
ruby
screen
texinfo
VPN" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305530" );
 script_set_attribute(attribute:"solution", value:
"Install Security Update 2007-005 :

http://www.apple.com/support/downloads/securityupdate2007005universal.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Check for the presence of Security Update 2007-004");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);



uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-9]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2007-00[5-9]|200[89]-|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
