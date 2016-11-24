
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-6411
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39406);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-6411: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-6411 (firefox)");
 script_set_attribute(attribute: "description", value: "Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance and portability.

-
Update Information:

Update to new upstream Firefox version 3.0.11, fixing multiple security issues
detailed in the upstream advisories:    [9]http://www.mozilla.org/security/know
n-
vulnerabilities/firefox30.html#firefox3.0.11    Update also includes all
packages depending on gecko-libs rebuild against new version of Firefox /
XULRunner.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841");
script_summary(english: "Check for the version of the firefox package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"firefox-3.0.11-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
