#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(18062);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2005-0969", "CVE-2005-0970", "CVE-2005-0971", "CVE-2005-0972", 
               "CVE-2005-0973", "CVE-2005-0974", "CVE-2005-0975", "CVE-2005-0976");
 script_bugtraq_id(13202, 13203, 13207, 13221, 13222, 13223, 13225);
 script_xref(name:"OSVDB", value:"15637");
 script_xref(name:"OSVDB", value:"15638");
 script_xref(name:"OSVDB", value:"15639");
 script_xref(name:"OSVDB", value:"15640");
 script_xref(name:"OSVDB", value:"15641");
 script_xref(name:"OSVDB", value:"15642");

 script_name(english:"Mac OS X < 10.3.9 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.3 which is older than
version 10.3.9.

Mac OS X 10.3.9 contains several security fixes for :

- Safari : a remote local zone script execution vulnerability has been fixed
- kernel : multiple local privilege escalation vulnerabilities have been fixed" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=301327" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.3.9" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

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

if ( ereg(pattern:"Mac OS X 10\.3\.[0-8]([^0-9]|$)", string:os )) security_hole(0);
