
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16041);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2004-687: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-687");
 script_set_attribute(attribute: "description", value: '
  Updated php packages that fix various security issues and bugs are now
  available for Red Hat Enterprise Linux 3.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  Flaws including possible information disclosure, double free, and negative
  reference index array underflow were found in the deserialization code of
  PHP. PHP applications may use the unserialize function on untrusted user
  data, which could allow a remote attacker to gain access to memory or
  potentially execute arbitrary code. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-1019 to
  this issue.

  A flaw in the exif extension of PHP was found which lead to a stack
  overflow. An attacker could create a carefully crafted image file in such
  a way that if parsed by a PHP script using the exif extension it could
  cause a crash or potentially execute arbitrary code. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-1065 to this issue.

  An information disclosure bug was discovered in the parsing of "GPC"
  variables in PHP (query strings or cookies, and POST form data). If
  particular scripts used the values of the GPC variables, portions of the
  memory space of an httpd child process could be revealed to the client.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2004-0958 to this issue.

  A file access bug was discovered in the parsing of "multipart/form-data"
  forms, used by PHP scripts which allow file uploads. In particular
  configurations, some scripts could allow a malicious client to upload files
  to an arbitrary directory where the "apache" user has write access. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-0959 to this issue.

  Flaws were found in shmop_write, pack, and unpack PHP functions. These
  functions are not normally passed user supplied data, so would require a
  malicious PHP script to be exploited. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-1018 to
  this issue.

  Various issues were discovered in the use of the "select" system call in
  PHP, which could be triggered if PHP is used in an Apache configuration
  where the number of open files (such as virtual host log files) exceeds the
  default process limit of 1024. Workarounds are now included for some of
  these issues.

  The "phpize" shell script included in PHP can be used to build third-party
  extension modules. A build issue was discovered in the "phpize" script on
  some 64-bit platforms which prevented correct operation.

  The "pcntl" extension module is now enabled in the command line PHP
  interpreter, /usr/bin/php. This module enables process control features
  such as "fork" and "kill" from PHP scripts.

  Users of PHP should upgrade to these updated packages, which contain fixes
  for these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-687.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0958", "CVE-2004-0959", "CVE-2004-1018", "CVE-2004-1019", "CVE-2004-1065");
script_summary(english: "Check for the version of the php packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"php-4.3.2-19.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.2-19.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.2-19.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.2-19.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.2-19.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.2-19.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.2-19.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
