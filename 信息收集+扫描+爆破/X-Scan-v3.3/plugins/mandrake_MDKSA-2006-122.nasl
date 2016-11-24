
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22053);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:122: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:122 (php).");
 script_set_attribute(attribute: "description", value: "Multiple buffer overflows in the gd graphics library (libgd) 2.0.21 and
earlier may allow remote attackers to execute arbitrary code via
malformed image files that trigger the overflows due to improper calls
to the gdMalloc function. One instance in gd_io_dp.c does not appear to
be corrected in the embedded copy of GD used in php to build the php-gd
package. (CVE-2004-0941)
Integer overflows were reported in the GD Graphics Library (libgd)
2.0.28, and possibly other versions. These overflows allow remote
attackers to cause a denial of service and possibly execute arbitrary
code via PNG image files with large image rows values that lead to a
heap-based buffer overflow in the gdImageCreateFromPngCtx() function.
PHP, as packaged in Mandriva Linux, contains an embedded copy of the
GD library, used to build the php-gd package. (CVE-2004-0990)
The c-client library 2000, 2001, or 2004 for PHP 3.x, 4.x, and 5.x,
when used in applications that accept user-controlled input for the
mailbox argument to the imap_open function, allow remote attackers to
obtain access to an IMAP stream data structure and conduct unauthorized
IMAP actions. (CVE-2006-1017)
Integer overflow in the wordwrap function in string.c in might allow
context-dependent attackers to execute arbitrary code via certain long
arguments that cause a small buffer to be allocated, which triggers a
heap-based buffer overflow in a memcpy function call, a different
vulnerability than CVE-2002-1396. (CVE-2006-1990) The previous update
for this issue did not resolve the issue on 64bit platforms.
The cURL library (libcurl) in PHP 4.4.2 and 5.1.4 allows attackers to
bypass safe mode and read files via a file:// request containing nul
characters. (CVE-2006-2563)
Buffer consumption vulnerability in the tempnam function in PHP 5.1.4
and 4.x before 4.4.3 allows local users to bypass restrictions and
create PHP files with fixed names in other directories via a pathname
argument longer than MAXPATHLEN, which prevents a unique string from
being appended to the filename. (CVE-2006-2660)
The LZW decoding in the gdImageCreateFromGifPtr function in the Thomas
Boutell graphics draw (GD) library (aka libgd) 2.0.33 allows remote
attackers to cause a denial of service (CPU consumption) via malformed
GIF data that causes an infinite loop. PHP, as packaged in Mandriva
Linux, contains an embedded copy of the GD library, used to build the
php-gd package. (CVE-2006-2906)
The error_log function in PHP allows local users to bypass safe mode
and open_basedir restrictions via a 'php://' or other scheme in the
third argument, which disables safe mode. (CVE-2006-3011)
An unspecified vulnerability in session.c in PHP before 5.1.3 has
unknown impact and attack vectors, related to 'certain characters in
session names', including special characters that are frequently
associated with CRLF injection, SQL injection, and cross-site scripting
(XSS) vulnerabilities. NOTE: while the nature of the vulnerability is
unspecified, it is likely that this is related to a violation of an
expectation by PHP applications that the session name is alphanumeric,
as implied in the PHP manual for session_name(). (CVE-2006-3016)
An unspecified vulnerability in PHP before 5.1.3 can prevent a variable
from being unset even when the unset function is called, which might
cause the variable's value to be used in security-relevant operations.
(CVE-2006-3017)
An unspecified vulnerability in the session extension functionality in
PHP before 5.1.3 has unkown impact and attack vectors related to heap
corruption. (CVE-2006-3018)
Multiple heap-based buffer overflows in the (1) str_repeat and (2) wordwrap
functions in ext/standard/string.c in PHP before 5.1.5, when used on a
64-bit system, have unspecified impact and attack vectors, a different
vulnerability than CVE-2006-1990. (CVE-2006-4482)
The cURL extension files (1) ext/curl/interface.c and (2) ext/curl/streams.c
in PHP before 5.1.5 permit the CURLOPT_FOLLOWLOCATION option when open_basedir
or safe_mode is enabled, which allows attackers to perform unauthorized
actions, possibly related to the realpath cache. (CVE-2006-4483)
Unspecified vulnerability in PHP before 5.1.6, when running on a 64-bit
system, has unknown impact and attack vectors related to the memory_limit
restriction. (CVE-2006-4486)
The GD related issues (CVE-2004-0941, CVE-2004-0990, CVE-2006-2906)
affect only Corporate 3 and Mandrake Network Firewall 2.
The php-curl issues (CVE-2006-2563, CVE-2006-4483) affect only Mandriva 2006.0.
Updated packages have been patched to address all these issues. Once
these packages have been installed, you will need to restart Apache
(service httpd restart) in order for the changes to take effect.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:122");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-1396", "CVE-2004-0941", "CVE-2004-0990", "CVE-2006-1017", "CVE-2006-1990", "CVE-2006-2563", "CVE-2006-2660", "CVE-2006-2906", "CVE-2006-3011", "CVE-2006-3016", "CVE-2006-3017", "CVE-2006-3018", "CVE-2006-4482", "CVE-2006-4483", "CVE-2006-4486");
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

if ( rpm_check( reference:"libphp_common432-4.3.10-7.14.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.10-7.14.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.10-7.14.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.10-7.14.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.10-6.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libphp5_common5-5.0.4-9.12.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.0.4-9.12.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.0.4-9.12.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-curl-5.0.4-1.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.0.4-9.12.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.0.4-9.12.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-5.0.4-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK10.2")
 || rpm_exists(rpm:"php-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2002-1396", value:TRUE);
 set_kb_item(name:"CVE-2004-0941", value:TRUE);
 set_kb_item(name:"CVE-2004-0990", value:TRUE);
 set_kb_item(name:"CVE-2006-1017", value:TRUE);
 set_kb_item(name:"CVE-2006-1990", value:TRUE);
 set_kb_item(name:"CVE-2006-2563", value:TRUE);
 set_kb_item(name:"CVE-2006-2660", value:TRUE);
 set_kb_item(name:"CVE-2006-2906", value:TRUE);
 set_kb_item(name:"CVE-2006-3011", value:TRUE);
 set_kb_item(name:"CVE-2006-3016", value:TRUE);
 set_kb_item(name:"CVE-2006-3017", value:TRUE);
 set_kb_item(name:"CVE-2006-3018", value:TRUE);
 set_kb_item(name:"CVE-2006-4482", value:TRUE);
 set_kb_item(name:"CVE-2006-4483", value:TRUE);
 set_kb_item(name:"CVE-2006-4486", value:TRUE);
}
exit(0, "Host is not affected");
