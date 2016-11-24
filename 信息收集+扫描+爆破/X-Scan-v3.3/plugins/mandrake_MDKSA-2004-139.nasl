
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15836);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2004:139: cyrus-imapd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:139 (cyrus-imapd).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities in the Cyrus-IMAP server were found by
Stefan Esser. Due to insufficient checking within the argument
parser of the 'partial' and 'fetch' commands, a buffer overflow could
be exploited to execute arbitrary attacker-supplied code. Another
exploitable buffer overflow could be triggered in situations when
memory allocation files.
The provided packages have been patched to prevent these problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:139");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-1011", "CVE-2004-1012", "CVE-2004-1013", "CVE-2004-1015");
script_summary(english: "Check for the version of the cyrus-imapd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cyrus-imapd-2.1.16-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-devel-2.1.16-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-murder-2.1.16-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-utils-2.1.16-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-2.1.16-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.2.8-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-devel-2.2.8-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-murder-2.2.8-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-nntp-2.2.8-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-utils-2.2.8-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-2.2.8-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"cyrus-imapd-", release:"MDK10.0")
 || rpm_exists(rpm:"cyrus-imapd-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1011", value:TRUE);
 set_kb_item(name:"CVE-2004-1012", value:TRUE);
 set_kb_item(name:"CVE-2004-1013", value:TRUE);
 set_kb_item(name:"CVE-2004-1015", value:TRUE);
}
exit(0, "Host is not affected");
