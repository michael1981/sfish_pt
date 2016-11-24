
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25721);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:146: perl-Net-DNS");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:146 (perl-Net-DNS).");
 script_set_attribute(attribute: "description", value: "A flaw was discovered in the perl Net::DNS module in the way it
generated the ID field in a DNS query. Because it is so predictable,
a remote attacker could exploit this to return invalid DNS data
(CVE-2007-3377).
A denial of service vulnerability was found in how Net::DNS parsed
certain DNS requests. A malformed response to a DNS request could
cause the application using Net::DNS to crash or stop responding
(CVE-2007-3409).
The updated packages have been patched to prevent these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:146");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-3377", "CVE-2007-3409");
script_summary(english: "Check for the version of the perl-Net-DNS package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"perl-Net-DNS-0.58-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-Net-DNS-0.59-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"perl-Net-DNS-", release:"MDK2007.0")
 || rpm_exists(rpm:"perl-Net-DNS-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-3377", value:TRUE);
 set_kb_item(name:"CVE-2007-3409", value:TRUE);
}
exit(0, "Host is not affected");
