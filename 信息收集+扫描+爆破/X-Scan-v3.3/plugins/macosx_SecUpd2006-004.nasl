#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if(description)
{
 script_id(22125);
 script_version ("$Revision: 1.10 $");

 script_cve_id("CVE-2005-0488", "CVE-2005-0988", "CVE-2005-1228", "CVE-2005-2335", "CVE-2005-3088",
               "CVE-2005-4348", "CVE-2006-0321", "CVE-2006-0392", "CVE-2006-0393", "CVE-2006-1472",
               "CVE-2006-1473", "CVE-2006-3459", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3465",
               "CVE-2006-3495", "CVE-2006-3496", "CVE-2006-3497", "CVE-2006-3498", "CVE-2006-3499",
               "CVE-2006-3500", "CVE-2006-3501", "CVE-2006-3502", "CVE-2006-3503", "CVE-2006-3504",
               "CVE-2006-3505");
 script_bugtraq_id(19289);
 script_xref(name:"OSVDB", value:"26930");
 script_xref(name:"OSVDB", value:"27731");
 script_xref(name:"OSVDB", value:"27732");
 script_xref(name:"OSVDB", value:"27733");
 script_xref(name:"OSVDB", value:"27735");
 script_xref(name:"OSVDB", value:"27736");
 script_xref(name:"OSVDB", value:"27737");
 script_xref(name:"OSVDB", value:"27738");
 script_xref(name:"OSVDB", value:"27739");
 script_xref(name:"OSVDB", value:"27740");
 script_xref(name:"OSVDB", value:"27741");
 script_xref(name:"OSVDB", value:"27742");
 script_xref(name:"OSVDB", value:"27743");
 script_xref(name:"OSVDB", value:"27744");
 script_xref(name:"OSVDB", value:"27745");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2006-004)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote operating system is missing a vendor supplied patch." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Apple Mac OS X, but lacks 
Security Update 2006-004. 

This security update contains fixes for the following
applications :

AFP Server
Bluetooth
Bom
DHCP
dyld
fetchmail
gnuzip
ImageIO
LaunchServices
OpenSSH
telnet
WebKit" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304063" );
 script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 :

http://www.apple.com/support/downloads/securityupdate2006004macosx1047clientintel.html
http://www.apple.com/support/downloads/securityupdate2006004macosx1047clientppc.html

Mac OS X 10.3 :

http://www.apple.com/support/downloads/securityupdate20060041039client.html
http://www.apple.com/support/downloads/securityupdate20060041039server.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Check for Security Update 2006-004");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-7]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2006-00[467]|2007-00[38])", string:packages)) security_hole(0);
}
