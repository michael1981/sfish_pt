
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15652);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2003-282: mysql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-282");
 script_set_attribute(attribute: "description", value: '
  Updated MySQL server packages fix a buffer overflow vulnerability.

  MySQL is a multi-user, multi-threaded SQL database server.

  Frank Denis reported a bug in unpatched versions of MySQL prior to version
  3.23.58. Passwords for MySQL users are stored in the Password field of the
  user table. Under this bug, a Password field with a value greater than 16
  characters can cause a buffer overflow. It may be possible for an attacker
  with the ability to modify the user table to exploit this buffer overflow
  to execute arbitrary code as the MySQL user. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2003-0780 to
  this issue.

  Users of MySQL are advised to upgrade to these erratum packages containing
  MySQL 3.23.58, which is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-282.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0780");
script_summary(english: "Check for the version of the mysql packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mysql-3.23.58-1.72", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.58-1.72", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-server-3.23.58-1.72", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
