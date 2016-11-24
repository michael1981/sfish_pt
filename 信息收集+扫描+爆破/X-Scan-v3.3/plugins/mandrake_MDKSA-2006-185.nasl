
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24570);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:185: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:185 (php).");
 script_set_attribute(attribute: "description", value: "PHP 4.x up to 4.4.4 and PHP 5 up to 5.1.6 allows local users to bypass
certain Apache HTTP Server httpd.conf options, such as safe_mode and
open_basedir, via the ini_restore function, which resets the values to
their php.ini (Master Value) defaults. (CVE-2006-4625)
A race condition in the symlink function in PHP 5.1.6 and earlier
allows local users to bypass the open_basedir restriction by using a
combination of symlink, mkdir, and unlink functions to change the file
path after the open_basedir check and before the file is opened by the
underlying system, as demonstrated by symlinking a symlink into a
subdirectory, to point to a parent directory via .. (dot dot)
sequences, and then unlinking the resulting symlink. (CVE-2006-5178)
Because the design flaw cannot be solved it is strongly recommended to
disable the symlink() function if you are using the open_basedir
feature. You can achieve that by adding symlink to the list of disabled
functions within your php.ini: disable_functions=...,symlink
The updated packages do not alter the system php.ini.
Updated packages have been patched to correct the CVE-2006-4625 issue.
Users must restart Apache for the changes to take effect.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:185");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-4625", "CVE-2006-5178");
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

if ( rpm_check( reference:"libphp5_common5-5.0.4-9.16.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.0.4-9.16.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.0.4-9.16.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.0.4-9.16.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.0.4-9.16.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libphp5_common5-5.1.6-1.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.1.6-1.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.1.6-1.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.1.6-1.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.1.6-1.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK2006.0")
 || rpm_exists(rpm:"php-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-4625", value:TRUE);
 set_kb_item(name:"CVE-2006-5178", value:TRUE);
}
exit(0, "Host is not affected");
