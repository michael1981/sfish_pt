
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21134);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0264: sendmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0264");
 script_set_attribute(attribute: "description", value: '
  Updated sendmail packages to fix a security issue are now available for Red
  Hat Enterprise Linux 3 and 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Sendmail is a Mail Transport Agent (MTA) used to send mail between machines.

  A flaw in the handling of asynchronous signals was discovered in Sendmail.
  A remote attacker may be able to exploit a race condition to execute
  arbitrary code as root. The Common Vulnerabilities and Exposures project
  assigned the name CVE-2006-0058 to this issue.

  By default on Red Hat Enterprise Linux 3 and 4, Sendmail is configured to
  only accept connections from the local host. Therefore, only users who have
  configured Sendmail to listen to remote hosts would be able to be remotely
  exploited by this vulnerability.

  Users of Sendmail are advised to upgrade to these erratum packages, which
  contain a backported patch from the Sendmail team to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0264.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-0058");
script_summary(english: "Check for the version of the sendmail packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sendmail-8.12.11-4.RHEL3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.11-4.RHEL3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.11-4.RHEL3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.11-4.RHEL3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.13.1-3.RHEL4.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.13.1-3.RHEL4.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.13.1-3.RHEL4.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.13.1-3.RHEL4.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
