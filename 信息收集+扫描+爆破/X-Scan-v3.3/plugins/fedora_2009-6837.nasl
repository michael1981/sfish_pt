
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-6837
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39508);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-6837: rt3");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-6837 (rt3)");
 script_set_attribute(attribute: "description", value: "RT is an enterprise-grade ticketing system which enables a group of people
to intelligently and efficiently manage tasks, issues, and requests submitted
by a community of users.

-
ChangeLog:


Update information :

* Fri Jun 19 2009 Ralf CorsÃ©pius <corsepiu fedoraproject org> - 3.8.2-8
- Address BZ #506885 (BZ #506236).
- Remove rt-3.4.1-I18N.diff.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the rt3 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"rt3-3.8.2-8.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
