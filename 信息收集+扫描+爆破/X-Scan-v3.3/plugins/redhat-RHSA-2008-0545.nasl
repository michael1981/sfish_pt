
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33511);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0545: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0545");
 script_set_attribute(attribute: "description", value: '
  Updated php packages that fix several security issues and a bug are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  It was discovered that the PHP escapeshellcmd() function did not properly
  escape multi-byte characters which are not valid in the locale used by the
  script. This could allow an attacker to bypass quoting restrictions imposed
  by escapeshellcmd() and execute arbitrary commands if the PHP script was
  using certain locales. Scripts using the default UTF-8 locale are not
  affected by this issue. (CVE-2008-2051)

  The PHP functions htmlentities() and htmlspecialchars() did not properly
  recognize partial multi-byte sequences. Certain sequences of bytes could be
  passed through these functions without being correctly HTML-escaped.
  Depending on the browser being used, an attacker could use this flaw to
  conduct cross-site scripting attacks. (CVE-2007-5898)

  A PHP script which used the transparent session ID configuration option, or
  which used the output_add_rewrite_var() function, could leak session
  identifiers to external web sites. If a page included an HTML form with an
  ACTION attribute referencing a non-local URL, the user\'s session ID would
  be included in the form data passed to that URL. (CVE-2007-5899)

  It was discovered that the PHP fnmatch() function did not restrict the
  length of the string argument. An attacker could use this flaw to crash the
  PHP interpreter where a script used fnmatch() on untrusted input data.
  (CVE-2007-4782)

  It was discovered that PHP did not properly seed its pseudo-random number
  generator used by functions such as rand() and mt_rand(), possibly allowing
  an attacker to easily predict the generated pseudo-random values.
  (CVE-2008-2107, CVE-2008-2108)

  As well, these updated packages fix the following bug:

  * after 2008-01-01, when using PEAR version 1.3.6 or older, it was not
  possible to use the PHP Extension and Application Repository (PEAR) to
  upgrade or install packages. In these updated packages, PEAR has been
  upgraded to version 1.4.9, which restores support for the current
  pear.php.net update server. The following changes were made to the PEAR
  packages included in php-pear: Console_Getopt and Archive_Tar are now
  included by default, and XML_RPC has been upgraded to version 1.5.0.

  All php users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0545.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4782", "CVE-2007-5898", "CVE-2007-5899", "CVE-2008-2051", "CVE-2008-2107", "CVE-2008-2108");
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

if ( rpm_check( reference:"php-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-domxml-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-gd-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ncurses-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-snmp-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-xmlrpc-4.3.9-3.22.12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
