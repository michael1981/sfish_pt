
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37164);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDKSA-2007:090: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:090 (php).");
 script_set_attribute(attribute: "description", value: "A heap-based buffer overflow vulnerability was found in PHP's gd
extension. A script that could be forced to process WBMP images
from an untrusted source could result in arbitrary code execution
(CVE-2007-1001).
A DoS flaw was found in how PHP processed a deeply nested array.
A remote attacker could cause the PHP intrerpreter to creash
by submitting an input variable with a deeply nested array
(CVE-2007-1285).
The internal filter module in PHP in certain instances did not properly
strip HTML tags, which allowed a remote attacker conduct cross-site
scripting (XSS) attacks (CVE-2007-1454).
A vulnerability in the way the mbstring extension set global variables
was discovered where a script using the mb_parse_str() function to
set global variables could be forced to to enable the register_globals
configuration option, possibly resulting in global variable injection
(CVE-2007-1583).
A vulnerability in how PHP's mail() function processed header data was
discovered. If a script sent mail using a subject header containing
a string from an untrusted source, a remote attacker could send bulk
email to unintended recipients (CVE-2007-1718).
Updated packages have been patched to correct these issues. Also note
that the default use of Suhosin helped to protect against some of
these issues prior to patching.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:090");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-1001", "CVE-2007-1285", "CVE-2007-1454", "CVE-2007-1583", "CVE-2007-1718");
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

if ( rpm_check( reference:"libphp5_common5-5.2.1-4.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.2.1-4.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.2.1-4.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.2.1-4.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.2.1-4.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-filter-5.2.1-0.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-gd-5.2.1-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-5.2.1-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-openssl-5.2.1-4.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-zlib-5.2.1-4.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-1001", value:TRUE);
 set_kb_item(name:"CVE-2007-1285", value:TRUE);
 set_kb_item(name:"CVE-2007-1454", value:TRUE);
 set_kb_item(name:"CVE-2007-1583", value:TRUE);
 set_kb_item(name:"CVE-2007-1718", value:TRUE);
}
exit(0, "Host is not affected");
