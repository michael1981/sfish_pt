
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40399);
 script_version("$Revision: 1.2 $");
 script_name(english: "MDVSA-2009:161-1: squid");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:161-1 (squid).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities has been found and corrected in squid:
Due to incorrect buffer limits and related bound checks Squid is
vulnerable to a denial of service attack when processing specially
crafted requests or responses (CVE-2009-2621).
Due to incorrect data validation Squid is vulnerable to a denial
of service attack when processing specially crafted responses
(CVE-2009-2622).
This update provides fixes for these vulnerabilities.
Update:
Additional upstream security patches were applied:
Debug warnings fills up the logs.
Upstream Bug 2728: regression: assertion failed: http.cc:705: !eof
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:161-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-2621", "CVE-2009-2622");
script_summary(english: "Check for the version of the squid package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"squid-3.0-1.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-cachemgr-3.0-1.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-3.0-8.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-cachemgr-3.0-8.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-3.0-14.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-cachemgr-3.0-14.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"squid-", release:"MDK2008.1")
 || rpm_exists(rpm:"squid-", release:"MDK2009.0")
 || rpm_exists(rpm:"squid-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-2621", value:TRUE);
 set_kb_item(name:"CVE-2009-2622", value:TRUE);
}
exit(0, "Host is not affected");
