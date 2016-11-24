#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17984);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(12993);
 script_cve_id("CVE-2005-0708");
 name["english"] = "FreeBSD : SA-05:02.sendfile";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of FreeBSD which contains a flaw in the 
sendfile() API.

There is an error in the sendfile() API which may allow a local user to disclose
parts of the contents of the kernel memory." );
 script_set_attribute(attribute:"solution", value:
"http://www.securityfocus.com/advisories/8356" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_end_attributes();

 
 summary["english"] = "Check for the version of the FreeBSD";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}



include("freebsd_package.inc");


package = get_kb_item("Host/FreeBSD/release");

if ( ! package ) exit(0);


if ( egrep(pattern:"FreeBSD-5\.", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.3_7") < 0 )
 {
  security_hole(0);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.[0-7][^0-9]", string:package) )
{
 security_hole(0);
 exit(0);
}

if ( egrep(pattern:"FreeBSD-4\.8[^0-9]", string:package) ) 
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.8_29") < 0 )
 {
  security_hole(0);
  exit(0);
 }
}


if ( egrep(pattern:"FreeBSD-4\.(9|10)", string:package) ) 
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.10_7") < 0 )
 {
  security_hole(0);
  exit(0);
 }
}


if ( egrep(pattern:"FreeBSD-4\.11", string:package) ) 
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.11_2") < 0 )
 {
  security_hole(0);
  exit(0);
 }
}
