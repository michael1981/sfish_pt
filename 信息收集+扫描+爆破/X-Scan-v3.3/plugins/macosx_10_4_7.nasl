#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(21763);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2006-1468", "CVE-2006-1469", "CVE-2006-1470", "CVE-2006-1471", "CVE-2006-1989");
 script_bugtraq_id(18686, 18724, 18728, 18731, 18733);
 script_xref(name:"OSVDB", value:"25120");
 script_xref(name:"OSVDB", value:"26930");
 script_xref(name:"OSVDB", value:"26931");
 script_xref(name:"OSVDB", value:"26932");
 script_xref(name:"OSVDB", value:"26933");

 script_name(english:"Mac OS X < 10.4.7 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.7.

Mac OS X 10.4.7 contains several security fixes for the following 
programs :

 - AFP server
 - ImageIO
 - launched
 - OpenLDAP" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=303973" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2006/Jun/msg00000.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.4.7 :
http://www.apple.com/support/downloads/macosxupdate1047intel.html
http://www.apple.com/support/downloads/macosxupdate1047ppc.html
http://www.apple.com/support/downloads/macosxserverupdate1047.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl","mdns.nasl", "ntp_open.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);
if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-6]([^0-9]|$))", string:os)) security_hole(0);
