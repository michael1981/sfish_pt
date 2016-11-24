#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12584);
 script_version ("$Revision: 1.4 $");
 name["english"] = "FreeBSD Ports : nap < 1.4.5";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host has an old version of nap installed.

This version of nap contains a security loophole which allows remote clients
to access arbitrary files on the nap system." );
 script_set_attribute(attribute:"solution", value:
"http://www.vuxml.org/freebsd/83119e27-5d7c-11d8-80e3-0020ed76ef5a.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_end_attributes();

 
 summary["english"] = "Check for the version of the nap package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}



include("freebsd_package.inc");


pkgs = get_kb_item("Host/FreeBSD/pkg_info");

package = egrep(pattern:"^nap-", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"nap-1.4.5") < 0 ) 
	security_hole(0);

