#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24354);
 script_version ("$Revision: 1.8 $");

 script_cve_id("CVE-2007-0021", "CVE-2007-0023", "CVE-2007-0197", "CVE-2007-0613", "CVE-2007-0614", "CVE-2007-0710");
 script_bugtraq_id(21980, 22146, 22188, 22304);
 script_xref(name:"OSVDB", value:"32695");
 script_xref(name:"OSVDB", value:"32698");
 script_xref(name:"OSVDB", value:"32699");
 script_xref(name:"OSVDB", value:"32713");
 script_xref(name:"OSVDB", value:"32714");
 script_xref(name:"OSVDB", value:"32715");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2007-002)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes several
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not
have Security Update 2007-002 applied. 

This update fixes security flaws in the following applications :

- Finder
- iChat
- UserNotification" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305102" );
 script_set_attribute(attribute:"solution", value:
"Install Security Update 2007-002 :

http://www.apple.com/support/downloads/securityupdate2007002universal.html
http://www.apple.com/support/downloads/securityupdate2007002panther.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Check for the presence of the SecUpdate 2007-002");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);



uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-8]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2007-00[2-9]|200[89]-|20[1-9][0-9]-)", string:packages)) 
    security_hole(0);
}
