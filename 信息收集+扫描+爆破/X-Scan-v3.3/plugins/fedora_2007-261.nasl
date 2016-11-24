
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-261
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24692);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2007-261: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-261 (php)");
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

A number of buffer overflow flaws were found in the PHP
session extension, the str_replace() function, and the
imap_mail_compose() function.  If very long strings under
the control of an attacker are passed to the str_replace()
function then an integer overflow could occur in memory
allocation.  If a script uses the imap_mail_compose()
function to create a new MIME message based on an input body
from an untrusted source, it could result in a heap
overflow.  An attacker who is able to access a PHP
application affected by any these issues could trigger these
flaws and possibly execute arbitrary code as the 'apache'
user. (CVE-2007-0906)

If unserializing untrusted data on 64-bit platforms, the
zend_hash_init() function can be forced to enter an infinite
loop, consuming CPU resources for a limited length of time,
until the script timeout alarm aborts execution of the
script. (CVE-2007-0988)

If the wddx extension is used to import WDDX data from an
untrusted source, certain WDDX input packets may allow a
random portion of heap memory to be exposed. (CVE-2007-0908)

If the odbc_result_all() function is used to display data
from a database, and the contents of the database table are
under the control of an attacker, a format string
vulnerability is possible which could lead to the execution
of arbitrary code.  (CVE-2007-0909)

A one byte memory read will always occur before the
beginning of a buffer, which could be triggered for example
by any use of the header() function in a script.  However it
is unlikely that this would have any effect. (CVE-2007-0907)

Several flaws in PHP could allows attackers to 'clobber'
certain super-global variables via unspecified vectors.
(CVE-2007-0910)

The Fedora Project would like to thank Stefan Esser for his
help diagnosing these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0988");
script_summary(english: "Check for the version of the php package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"php-ldap-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-soap-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-gd-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-xml-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-dba-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-snmp-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mysql-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pdo-5.1.6-3.4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
