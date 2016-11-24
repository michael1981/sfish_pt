
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(41050);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:242: dovecot");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:242 (dovecot).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered and corrected in dovecot:
Multiple stack-based buffer overflows in the Sieve plugin in Dovecot
1.0 before 1.0.4 and 1.1 before 1.1.7, as derived from Cyrus libsieve,
allow context-dependent attackers to cause a denial of service
(crash) and possibly execute arbitrary code via a crafted SIEVE
script, as demonstrated by forwarding an e-mail message to a large
number of recipients, a different vulnerability than CVE-2009-2632
(CVE-2009-3235).
This update provides a solution to this vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:242");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-2632", "CVE-2009-3235");
script_summary(english: "Check for the version of the dovecot package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dovecot-1.1.6-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dovecot-devel-1.1.6-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dovecot-plugins-gssapi-1.1.6-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dovecot-plugins-ldap-1.1.6-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"dovecot-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-2632", value:TRUE);
 set_kb_item(name:"CVE-2009-3235", value:TRUE);
}
exit(0, "Host is not affected");
