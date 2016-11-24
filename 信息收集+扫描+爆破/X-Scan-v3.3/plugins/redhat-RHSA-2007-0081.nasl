
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24697);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0081: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0081");
 script_set_attribute(attribute: "description", value: '
  Updated PHP packages that fix several security issues are now available for
  Red Hat Enterprise Linux 2.1.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  A number of buffer overflow flaws were found in the PHP session extension;
  the str_replace() function; and the imap_mail_compose() function. If very
  long strings were passed to the str_replace() function, an integer
  overflow could occur in memory allocation. If a script used the
  imap_mail_compose() function to create a new MIME message based on an
  input body from an untrusted source, it could result in a heap overflow.
  An attacker with access to a PHP application affected by any these issues
  could trigger the flaws and possibly execute arbitrary code as the
  \'apache\' user. (CVE-2007-0906)

  When unserializing untrusted data on 64-bit platforms, the
  zend_hash_init() function could be forced into an infinite loop, consuming
  CPU resources for a limited time, until the script timeout alarm aborted
  execution of the script. (CVE-2007-0988)

  If the wddx extension was used to import WDDX data from an untrusted
  source, certain WDDX input packets could expose a random portion of heap
  memory. (CVE-2007-0908)

  If the odbc_result_all() function was used to display data from a database,
  and the database table contents were under an attacker\'s control, a format
  string vulnerability was possible which could allow arbitrary code
  execution. (CVE-2007-0909)

  A one byte memory read always occurs before the beginning of a buffer. This
  could be triggered, for example, by any use of the header() function in a
  script. However it is unlikely that this would have any effect.
  (CVE-2007-0907)

  Several flaws in PHP could allow attackers to "clobber" certain
  super-global variables via unspecified vectors. (CVE-2007-0910)

  Users of PHP should upgrade to these updated packages which contain
  backported patches to correct these issues.

  Red Hat would like to thank Stefan Esser for his help diagnosing these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0081.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0988", "CVE-2007-1380", "CVE-2007-1701", "CVE-2007-1825");
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

if ( rpm_check( reference:"php-4.1.2-2.14", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.1.2-2.14", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.1.2-2.14", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.1.2-2.14", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-manual-4.1.2-2.14", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.1.2-2.14", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.1.2-2.14", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.1.2-2.14", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
