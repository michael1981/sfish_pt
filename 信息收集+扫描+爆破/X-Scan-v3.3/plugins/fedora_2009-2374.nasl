
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2374
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35783);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2009-2374: dkim-milter");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2374 (dkim-milter)");
 script_set_attribute(attribute: "description", value: "The dkim-milter package is an open source implementation of the DKIM
sender authentication system proposed by the E-mail Signing Technology
Group (ESTG), now a proposed standard of the IETF (RFC4871).

DKIM is an amalgamation of the DomainKeys (DK) proposal by Yahoo!, Inc.
and the Internet Identified Mail (IIM) proposal by Cisco.

This package consists of a library that implements the DKIM service and a
milter-based filter application that can plug in to the sendmail MTA to
provide that service to sufficiently recent sendmail MTAs and other MTAs
that support the milter protocol.

-
Update Information:

updated to 2.8.1 (security #488595)
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the dkim-milter package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"dkim-milter-2.8.1-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
