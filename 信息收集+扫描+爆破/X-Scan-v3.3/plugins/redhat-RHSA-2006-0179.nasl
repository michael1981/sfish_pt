
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20400);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0179: auth_ldap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0179");
 script_set_attribute(attribute: "description", value: '
  An updated auth_ldap packages that fixes a format string security issue is
  now available for Red Hat Enterprise Linux 2.1.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The auth_ldap package is an httpd module that allows user authentication
  against information stored in an LDAP database.

  A format string flaw was found in the way auth_ldap logs information. It
  may be possible for a remote attacker to execute arbitrary code as the
  \'apache\' user if auth_ldap is used for user authentication. The Common
  Vulnerabilities and Exposures project assigned the name CVE-2006-0150
  to this issue.

  Note that this issue only affects servers that have auth_ldap installed and
  configured to perform user authentication against an LDAP database.

  All users of auth_ldap should upgrade to this updated package, which
  contains a backported patch to resolve this issue.

  This issue does not affect the Red Hat Enterprise Linux 3 or 4
  distributions as they do not include the auth_ldap package.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0179.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-0150");
script_summary(english: "Check for the version of the auth_ldap packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"auth_ldap-1.4.8-3.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
