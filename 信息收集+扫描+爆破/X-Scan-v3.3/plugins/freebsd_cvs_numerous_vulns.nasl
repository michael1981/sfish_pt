#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14812);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(10499);
 name["english"] = "FreeBSD : SA-04:14.cvs";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of FreeBSD which contains a
version of the 'cvs' utility containing several issues :

- An insufficient input validation while processing 'Entry' lines
- A double-free issue
- An integer overflow when processing 'Max-dotdot' commands
- A format string bug when processing cvs wrappers
- A single-byte buffer overflow when processing configuration files
- Various other integers overflows" );
 script_set_attribute(attribute:"solution", value:
"http://www.vuxml.org/freebsd/d2102505-f03d-11d8-81b0-000347a4fa7d.html" );
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");


 script_end_attributes();

 
 summary["english"] = "Check for the version of the FreeBSD";
 script_cve_id("CVE-2004-0414", "CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418", "CVE-2004-1471");
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

pkgs = get_kb_item("Host/FreeBSD/pkg_info");

package = egrep(pattern:"^cvs+ipv6", string:pkgs);
if ( package )
{
if ( pkg_cmp(pkg:package, reference:"cvs+ipv6-1.11.17") < 0 ) 
        {
        security_hole(0);
        exit(0);
        }
}



package = get_kb_item("Host/FreeBSD/release");

if ( ! package ) exit(0);


if ( egrep(pattern:"FreeBSD-5\.", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-5.2.1_10") < 0 )
 {
  security_hole(0);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.[0-8]([^0-9]|$)", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.8_25") < 0 )
 {
  security_hole(0);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.9", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.9_12") < 0 )
 {
  security_hole(0);
  exit(0);
 }
}

if ( egrep(pattern:"FreeBSD-4\.10", string:package) )
{
 if ( pkg_cmp(pkg:package, reference:"FreeBSD-4.10_3") < 0 )
 {
  security_hole(0);
  exit(0);
 }
}

