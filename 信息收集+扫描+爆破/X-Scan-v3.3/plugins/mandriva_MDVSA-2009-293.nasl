
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42356);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:293: squidGuard");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:293 (squidGuard).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities has been found and corrected in squidGuard:
Buffer overflow in sgLog.c in squidGuard 1.3 and 1.4 allows remote
attackers to cause a denial of service (application hang or loss of
blocking functionality) via a long URL with many / (slash) characters,
related to emergency mode. (CVE-2009-3700).
Multiple buffer overflows in squidGuard 1.4 allow remote attackers
to bypass intended URL blocking via a long URL, related to (1)
the relationship between a certain buffer size in squidGuard and a
certain buffer size in Squid and (2) a redirect URL that contains
information about the originally requested URL (CVE-2009-3826).
squidGuard was upgraded to 1.2.1 for MNF2/CS3/CS4 with additional
upstream security and bug fixes patches applied.
This update fixes these vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:293");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-3700", "CVE-2009-3826");
script_summary(english: "Check for the version of the squidGuard package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"squidGuard-1.3-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squidGuard-1.4-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"squidGuard-", release:"MDK2009.0")
 || rpm_exists(rpm:"squidGuard-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-3700", value:TRUE);
 set_kb_item(name:"CVE-2009-3826", value:TRUE);
}
exit(0, "Host is not affected");
