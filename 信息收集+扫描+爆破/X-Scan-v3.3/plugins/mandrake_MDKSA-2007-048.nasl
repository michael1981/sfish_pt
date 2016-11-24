
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24695);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:048: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:048 (php).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered in PHP language.
Many buffer overflow flaws were discovered in the PHP session
extension, the str_replace() function, and the imap_mail_compose()
function. An attacker able to use a PHP application using any of
these functions could trigger these flaws and possibly execute
arbitrary code as the apache user (CVE-2007-0906).
A one-byte memory read will always occur prior to the beginning of a
buffer, which could be triggered, for example, by any use of the
header() function in a script (CVE-2007-0907).
The wddx extension, if used to import WDDX data from an untrusted
source, may allow a random portion of heap memory to be exposed due
to certain WDDX input packets (CVE-2007-0908).
The odbc_result_all() function, if used to display data from a
database,
and if the contents of the database are under the control of an
attacker, could lead to the execution of arbitrary code due to a format
string vulnerability (CVE-2007-0909).
Several flaws in the PHP could allow attackers to clobber certain
super-global variables via unspecified vectors (CVE-2007-0910).
The zend_hash_init() function can be forced into an infinite loop
if unserializing untrusted data on a 64-bit platform, resulting in
the consumption of CPU resources until the script timeout alarm aborts
the execution of the script (CVE-2007-0988).
Updated package have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:048");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0988");
script_summary(english: "Check for the version of the php package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libphp5_common5-5.0.4-9.19.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.0.4-9.19.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.0.4-9.19.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.0.4-9.19.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.0.4-9.19.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-5.0.4-2.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-5.0.4-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-session-5.0.4-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libphp5_common5-5.1.6-1.6mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.1.6-1.6mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.1.6-1.6mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.1.6-1.6mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.1.6-1.6mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-5.1.6-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-5.1.6-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-session-5.1.6-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK2006.0")
 || rpm_exists(rpm:"php-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2007-0906", value:TRUE);
 set_kb_item(name:"CVE-2007-0907", value:TRUE);
 set_kb_item(name:"CVE-2007-0908", value:TRUE);
 set_kb_item(name:"CVE-2007-0909", value:TRUE);
 set_kb_item(name:"CVE-2007-0910", value:TRUE);
 set_kb_item(name:"CVE-2007-0988", value:TRUE);
}
exit(0, "Host is not affected");
