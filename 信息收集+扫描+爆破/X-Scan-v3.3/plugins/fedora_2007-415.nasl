
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-415
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25046);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2007-415: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-415 (php)");
 script_set_attribute(attribute: "description", value: "PHP is an HTML-embedded scripting language. PHP attempts to make it
easy for developers to write dynamically generated webpages. PHP also
offers built-in database integration for several commercial and
non-commercial database management systems, so writing a
database-enabled webpage with PHP is fairly simple. The most common
use of PHP coding is probably as a replacement for CGI scripts.

The php package contains the module which adds support for the PHP
language to Apache HTTP Server.

Update Information:

This update fixes a number of security issues in PHP.

A denial of service flaw was found in the way PHP processed
a deeply nested array. A remote attacker could cause the PHP
interpreter to crash by submitting an input variable with a
deeply nested array. (CVE-2007-1285)

A flaw was found in the way the mbstring extension set
global variables. A script which used the mb_parse_str()
function to set global variables could be forced to enable
the register_globals configuration option, possibly
resulting in global variable injection. (CVE-2007-1583)

A flaw was discovered in the way PHP's mail() function
processed header data. If a script sent mail using a Subject
header containing a string from an untrusted source, a
remote attacker could send bulk e-mail to unintended
recipients. (CVE-2007-1718)

A heap based buffer overflow flaw was discovered in PHP's gd
extension. A script that could be forced to process WBMP
images from an untrusted source could result in arbitrary
code execution. (CVE-2007-1001)

A buffer over-read flaw was discovered in PHP's gd
extension. A script that could be forced to write arbitrary
strings using a JIS font from an untrusted source could
cause the PHP interpreter to crash. (CVE-2007-0455)

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-0455", "CVE-2007-1001", "CVE-2007-1285", "CVE-2007-1583", "CVE-2007-1718");
script_summary(english: "Check for the version of the php package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"php-pgsql-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-snmp-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mysql-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-xml-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-dba-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ldap-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pdo-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-soap-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-gd-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.1.6-3.5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
