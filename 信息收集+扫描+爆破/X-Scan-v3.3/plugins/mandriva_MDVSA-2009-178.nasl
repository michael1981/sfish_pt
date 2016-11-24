
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(41950);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:178: perl-IO-Socket-SSL");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:178 (perl-IO-Socket-SSL).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered and corrected in perl-IO-Socket-SSL:
The verify_hostname_of_cert function in the certificate checking
feature in IO-Socket-SSL (IO::Socket::SSL) 1.14 through 1.25 only
matches the prefix of a hostname when no wildcard is used, which
allows remote attackers to bypass the hostname check for a certificate
(CVE-2009-3024).
This update provides a fix for this vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:178");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-3024");
script_summary(english: "Check for the version of the perl-IO-Socket-SSL package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"perl-IO-Socket-SSL-1.15-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-IO-Socket-SSL-1.15-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"perl-IO-Socket-SSL-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-3024", value:TRUE);
}
exit(0, "Host is not affected");
