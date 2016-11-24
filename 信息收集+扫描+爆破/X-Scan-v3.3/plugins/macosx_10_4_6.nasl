#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(21175);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2006-0401");
 script_bugtraq_id(17364);
 script_xref(name:"OSVDB", value:"24399");

 script_name(english:"Mac OS X < 10.4.6 Firmware Unspecified Password Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.6.

Mac OS X 10.4.6 contains a security fix for a local authentication
bypass vulnerability. A malicious local user may exploit this vulnerability
to bypass the firmware password and gain access to Single User mode.

This vulnerability only affects intel-based Macintoshes." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=303567" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.4.6 :

http://www.apple.com/support/downloads/macosx1046forintel.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl","mdns.nasl", "ntp_open.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);
uname = get_kb_item("Host/uname");
if ( uname )
{
 if ("i386" >!< uname ) exit(0);
}
else
{
 ntp  = get_kb_item("Host/processor/ntp");
 if ( ! ntp|| "i386" >!< ntp ) exit(0);
}

if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-5]([^0-9]|$))", string:os)) security_warning(0);
