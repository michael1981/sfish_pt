#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(18353);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2005-1472", "CVE-2005-1473", "CVE-2005-1474");
 script_bugtraq_id(13694, 13695, 13696);
 script_xref(name:"OSVDB", value:"16499");
 script_xref(name:"OSVDB", value:"16725");
 script_xref(name:"OSVDB", value:"16726");

 script_name(english:"Mac OS X < 10.4.1 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.1.

Mac OS X 10.4.1 contains several security fixes for :

- Bluetooth
- Dashboard
- Kernel
- SecurityAgent" );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/TA23244?viewlocale=en_US" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.4.1" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl", "mdns.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);

if ( ereg(pattern:"Mac OS X 10\.4$", string:os )) security_warning(0);
