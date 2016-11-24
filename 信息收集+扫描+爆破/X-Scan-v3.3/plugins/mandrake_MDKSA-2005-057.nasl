
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17334);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:057: gnupg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:057 (gnupg).");
 script_set_attribute(attribute: "description", value: "The OpenPGP protocol is vulnerable to a timing-attack in order to
gain plain text from cipher text. The timing difference appears as a
side effect of the so-called 'quick scan' and is only exploitable on
systems that accept an arbitrary amount of cipher text for automatic
decryption.
The updated packages have been patched to disable the quick check for
all public key-encrypted messages and files.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:057");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0366");
script_summary(english: "Check for the version of the gnupg package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gnupg-1.2.4-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.4-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.3-3.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gnupg-", release:"MDK10.0")
 || rpm_exists(rpm:"gnupg-", release:"MDK10.1")
 || rpm_exists(rpm:"gnupg-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2005-0366", value:TRUE);
}
exit(0, "Host is not affected");
