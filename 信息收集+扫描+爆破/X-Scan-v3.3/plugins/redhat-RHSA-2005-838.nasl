
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20207);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2005-838: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-838");
 script_set_attribute(attribute: "description", value: '
  Updated PHP packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 2.1

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  A flaw was found in the way PHP registers global variables during a file
  upload request. A remote attacker could submit a carefully crafted
  multipart/form-data POST request that would overwrite the $GLOBALS array,
  altering expected script behavior, and possibly leading to the execution of
  arbitrary PHP commands. Note that this vulnerability only affects
  installations which have register_globals enabled in the PHP configuration
  file, which is not a default or recommended option. The Common
  Vulnerabilities and Exposures project assigned the name CVE-2005-3390 to
  this issue.

  A flaw was found in the PHP parse_str() function. If a PHP script passes
  only one argument to the parse_str() function, and the script can be forced
  to abort execution during operation (for example due to the memory_limit
  setting), the register_globals may be enabled even if it is disabled in the
  PHP configuration file. This vulnerability only affects installations that
  have PHP scripts using the parse_str function in this way. (CVE-2005-3389)

  A Cross-Site Scripting flaw was found in the phpinfo() function. If a
  victim can be tricked into following a malicious URL to a site with a page
  displaying the phpinfo() output, it may be possible to inject javascript
  or HTML content into the displayed page or steal data such as cookies.
  This vulnerability only affects installations which allow users to view the
  output of the phpinfo() function. As the phpinfo() function outputs a
  large amount of information about the current state of PHP, it should only
  be used during debugging or if protected by authentication. (CVE-2005-3388)

  Additionally, a bug introduced in the updates to fix CVE-2004-1019 has been
  corrected.

  Users of PHP should upgrade to these updated packages, which contain
  backported patches that resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-838.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3388", "CVE-2005-3389", "CVE-2005-3390");
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

if ( rpm_check( reference:"php-4.1.2-2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.1.2-2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.1.2-2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.1.2-2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-manual-4.1.2-2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.1.2-2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.1.2-2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.1.2-2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
