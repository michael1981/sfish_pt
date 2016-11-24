#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(20113);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2005-1126", "CVE-2005-1406", "CVE-2005-2739", "CVE-2005-2749",
               "CVE-2005-2750", "CVE-2005-2751", "CVE-2005-2752");
 script_bugtraq_id(15252);
 script_xref(name:"OSVDB", value:"15514");
 script_xref(name:"OSVDB", value:"16091");
 script_xref(name:"OSVDB", value:"20427");
 script_xref(name:"OSVDB", value:"20428");
 script_xref(name:"OSVDB", value:"20429");
 script_xref(name:"OSVDB", value:"20430");
 script_xref(name:"OSVDB", value:"20431");

 script_name(english:"Mac OS X < 10.4.3 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes security
issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.3.

Mac OS X 10.4.3 contains several security fixes for :

- Finder
- Software Update
- memberd
- KeyChain
- Kernel" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.4.3 :
http://www.apple.com/support/downloads/macosxupdate1043.html
http://www.apple.com/support/downloads/macosxserver1043.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2005/Oct/msg00000.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N" );

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

if ( ereg(pattern:"Mac OS X 10\.4($|\.[12]([^0-9]|$))", string:os )) security_note(0);
