
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-1024
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24032);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2006-1024: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-1024 (php)");
 script_set_attribute(attribute: "description", value: "PHP is an HTML-embedded scripting language. PHP attempts to make it
easy for developers to write dynamically generated webpages. PHP also
offers built-in database integration for several commercial and
non-commercial database management systems, so writing a
database-enabled webpage with PHP is fairly simple. The most common
use of PHP coding is probably as a replacement for CGI scripts. The
mod_php module enables the Apache Web server to understand and process
the embedded PHP language in Web pages.

Update Information:

This update includes the latest upstream release of PHP 5.1,
version 5.1.6, fixing a number of security vulnerabilities,
and other bugs.

An integer overflow was discovered in the PHP memory
handling routines. If a script can cause memory allocation
based on untrusted user data, a remote attacker sending a
carefully crafted request could execute arbitrary code
as the 'apache' user. (CVE-2006-4812)

A buffer overflow was discovered in the PHP sscanf()
function. If a script used the sscanf() function with
positional arguments in the format string, a remote attacker
sending a carefully crafted request could execute arbitrary
code as the 'apache' user. (CVE-2006-4020)

An integer overflow was discovered in the PHP wordwrap() and
str_repeat() functions. If a script running on a 64-bit
server used either of these functions on untrusted user
data, a remote attacker sending a carefully crafted request
might be able to cause a heap overflow. (CVE-2006-4482)

A buffer overflow was discovered in the PHP gd extension. If
a script was set up to process GIF images from untrusted
sources using the gd extension, a remote attacker could
cause a heap overflow. (CVE-2006-4484)

A buffer overread was discovered in the PHP stripos()
function. If a script used the stripos() function with
untrusted user data, PHP may read past the end of a buffer,
which could allow a denial of service attack by a remote
user. (CVE-2006-4485)

An integer overflow was discovered in the PHP memory
allocation handling. On 64-bit platforms, the 'memory_limit'
setting was not enforced correctly, which could allow a
denial of service attack by a remote user. (CVE-2006-4486)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-4020", "CVE-2006-4482", "CVE-2006-4484", "CVE-2006-4485", "CVE-2006-4486", "CVE-2006-4812");
script_summary(english: "Check for the version of the php package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"php-mysql-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-snmp-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ncurses-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ldap-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-gd-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-xmlrpc-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-dba-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-bcmath-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-soap-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pdo-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-xml-5.1.6-1.1", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
