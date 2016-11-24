
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36350);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:073: perl-Net-DNS");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:073 (perl-Net-DNS).");
 script_set_attribute(attribute: "description", value: "A vulnerability in the Net::DNS perl module was found that could
allow remote attackers to cause a denial of service via a crafted
DNS response.
The updated packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:073");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-6341");
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

if ( rpm_check( reference:"perl-Net-DNS-0.58-1.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-Net-DNS-0.59-1.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-Net-DNS-0.61-1.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"perl-Net-DNS-", release:"MDK2007.0")
 || rpm_exists(rpm:"perl-Net-DNS-", release:"MDK2007.1")
 || rpm_exists(rpm:"perl-Net-DNS-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2007-6341", value:TRUE);
}
exit(0, "Host is not affected");
