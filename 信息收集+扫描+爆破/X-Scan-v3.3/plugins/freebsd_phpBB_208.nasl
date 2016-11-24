#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12592);
 script_bugtraq_id(9942);
 script_version ("$Revision: 1.5 $");
 name["english"] = "FreeBSD Ports: phpBB < 2.0.8";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host has an old version of phpBB installed.

phpBB is a PHP-based bulletin board. There is a cross-site
scripting issue in the remote version of this software which 
may allow an attacker to damage the remote phpBB installation" );
 script_set_attribute(attribute:"solution", value:
"http://www.vuxml.org/freebsd/c480eb5e-7f00-11d8-868e-000347dd607f.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );


 script_end_attributes();

 
 summary["english"] = "Check for the version of the phpbb package";
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

package = egrep(pattern:"^phpbb-", string:pkgs);
if ( pkg_cmp(pkg:package, reference:"phpbb-2.0.8") < 0 ) 
	security_warning(0);
