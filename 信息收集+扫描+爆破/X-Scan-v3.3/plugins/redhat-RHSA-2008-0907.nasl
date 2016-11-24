
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34333);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0907: pam_krb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0907");
 script_set_attribute(attribute: "description", value: '
  An updated pam_krb5 package that fixes a security issue is now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The pam_krb5 module allows Pluggable Authentication Modules (PAM) aware
  applications to use Kerberos to verify user identities by obtaining user
  credentials at log in time.

  A flaw was found in the pam_krb5 "existing_ticket" configuration option. If
  a system is configured to use an existing credential cache via the
  "existing_ticket" option, it may be possible for a local user to gain
  elevated privileges by using a different, local user\'s credential cache.
  (CVE-2008-3825)

  Red Hat would like to thank St  phane Bertin for responsibly disclosing
  this
  issue.

  Users of pam_krb5 should upgrade to this updated package, which contains a
  backported patch to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0907.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-3825");
script_summary(english: "Check for the version of the pam_krb packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pam_krb5-2.2.14-1.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
