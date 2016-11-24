#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12575);
 script_bugtraq_id(9533);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0099");
 name["english"] = "FreeBSD : SA-04:01.mksnap_ff";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of FreeBSD which contains a
bug in the mksnap_ffs(8) utility which may reset file flags on
the remote file system, thus resetting the type of access control
that were assigned to a file." );
 script_set_attribute(attribute:"solution", value:
"http://www.vuxml.org/freebsd/7229d900-88af-11d8-90d1-0020ed76ef5a.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );


 script_end_attributes();

 
 summary["english"] = "Check for the version of the FreeBSD";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}



include("freebsd_package.inc");

port = 0;

package = get_kb_item("Host/FreeBSD/release");


if ( egrep(pattern:"FreeBSD-5\.1", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.1_12") < 0 )
 {
  security_warning(port);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-5\.2", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.2_1") < 0 )
 {
  security_warning(port);
  exit(0);
 }
}
