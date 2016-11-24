#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(18683);
 script_version ("$Revision: 1.13 $");

 script_cve_id("CVE-2005-1333", "CVE-2005-1474", "CVE-2005-2194");
 script_bugtraq_id(14241);
 script_xref(name:"OSVDB", value:"16074");
 script_xref(name:"OSVDB", value:"16499");
 script_xref(name:"OSVDB", value:"17880");
 script_xref(name:"IAVA", value:"2005-t-0015");

 script_name(english:"Mac OS X < 10.4.2 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host may be affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 which is older
than version 10.4.2.  Mac OS X 10.4.2 contains several security fixes
for :

- TCP/IP
- Dashboard
- Bluetooth File and Object Exchange" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=301948" );
 script_set_attribute(attribute:"solution", value:
"Apply the Mac OS X 10.4.2 Update." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Check the version of Mac OS X");
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

if ( ereg(pattern:"Mac OS X 10\.4($|\.1([^0-9]|$))", string:os )) security_warning(0);
