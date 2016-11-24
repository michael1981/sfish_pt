
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-0636
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35456);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2009-0636: libnasl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-0636 (libnasl)");
 script_set_attribute(attribute: "description", value: "NASL is a scripting language designed for the Nessus security scanner.
Its aim is to allow anyone to write a test for a given security hole
in a few minutes, to allow people to share their tests without having
to worry about their operating system, and to guarantee everyone that
a NASL script can not do anything nasty except performing a given
security test against a given target.

Thus, NASL allows you to easily forge IP packets, or to send regular
packets. It provides you some convenient functions that will make the
test of web and FTP server more easy to write. NASL garantees you that
a NASL script:
- will not send any packet to a host other than the target host,
- will not execute any commands on your local system.

-
ChangeLog:


Update information :

* Mon Jan 12 2009 Andreas Bierfert <andreas.bierfert[AT]lowlatency.de>
- 2.2.11-3
- fix #479655
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the libnasl package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libnasl-2.2.11-3.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
