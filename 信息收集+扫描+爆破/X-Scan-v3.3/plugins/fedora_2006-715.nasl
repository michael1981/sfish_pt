
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-715
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24129);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 5 2006-715: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-715 (firefox)");
 script_set_attribute(attribute: "description", value: "Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance and portability.

Update Information:

Several security issues have been identified that are fixed
in this release. Please refer to
[8]http://www.mozilla.org/projects/security/known-vulnerabilities.html#firefox1
.5.0.4
for details.

Users of Firefox are advised to update to this package,
which contains version 1.5.0.4 of Firefox and is not
vulnerable to these issues.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the firefox package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"firefox-1.5.0.4-1.2.fc5", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
