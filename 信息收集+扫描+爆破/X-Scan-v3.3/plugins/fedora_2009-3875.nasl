
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-3875
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37309);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-3875: blam");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-3875 (blam)");
 script_set_attribute(attribute: "description", value: "Blam is a tool that helps you keep track of the growing
number of news feeds distributed as RSS. Blam lets you
subscribe to any number of feeds and provides an easy to
use and clean interface to stay up to date

-
Update Information:

[9]http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.9
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0652", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1310", "CVE-2009-1311", "CVE-2009-1312");
script_summary(english: "Check for the version of the blam package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"blam-1.8.5-8.fc9.1", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
