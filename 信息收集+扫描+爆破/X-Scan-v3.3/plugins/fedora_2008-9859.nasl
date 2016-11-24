
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-9859
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34837);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-9859: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-9859 (thunderbird)");
 script_set_attribute(attribute: "description", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

-
Update Information:

This update update upgrades thunderbird packages to upstream version 2.0.0.18,
which fixes multiple security issues detailed in upstream security advisories:
[9]http://www.mozilla.org/security/known-
vulnerabilities/thunderbird20.html#thunderbird2.0.0.17
[10]http://www.mozilla.org/security/known-
vulnerabilities/thunderbird20.html#thunderbird2.0.0.18
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0016", "CVE-2008-3835", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4070", "CVE-2008-5012", "CVE-2008-5014", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5024");
script_summary(english: "Check for the version of the thunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"thunderbird-2.0.0.18-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
