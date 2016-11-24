
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36097);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0337: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0337");
 script_set_attribute(attribute: "description", value: '
  Updated php packages that fix several security issues are now available for
  Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  A heap-based buffer overflow flaw was found in PHP\'s mbstring extension. A
  remote attacker able to pass arbitrary input to a PHP script using mbstring
  conversion functions could cause the PHP interpreter to crash or,
  possibly, execute arbitrary code. (CVE-2008-5557)

  A flaw was found in the handling of the "mbstring.func_overload"
  configuration setting. A value set for one virtual host, or in a user\'s
  .htaccess file, was incorrectly applied to other virtual hosts on the same
  server, causing the handling of multibyte character strings to not work
  correctly. (CVE-2009-0754)

  A buffer overflow flaw was found in PHP\'s imageloadfont function. If a PHP
  script allowed a remote attacker to load a carefully crafted font file, it
  could cause the PHP interpreter to crash or, possibly, execute arbitrary
  code. (CVE-2008-3658)

  A flaw was found in the way PHP handled certain file extensions when
  running in FastCGI mode. If the PHP interpreter was being executed via
  FastCGI, a remote attacker could create a request which would cause the PHP
  interpreter to crash. (CVE-2008-3660)

  A memory disclosure flaw was found in the PHP gd extension\'s imagerotate
  function. A remote attacker able to pass arbitrary values as the
  "background color" argument of the function could, possibly, view portions
  of the PHP interpreter\'s memory. (CVE-2008-5498)

  All php users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. The httpd web server
  must be restarted for the changes to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0337.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-3658", "CVE-2008-3660", "CVE-2008-5498", "CVE-2008-5557", "CVE-2009-0754");
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

if ( rpm_check( reference:"php-4.3.2-51.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.2-51.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.2-51.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.2-51.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.2-51.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.2-51.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.2-51.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-domxml-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-gd-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ncurses-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-snmp-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-xmlrpc-4.3.9-3.22.15", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
