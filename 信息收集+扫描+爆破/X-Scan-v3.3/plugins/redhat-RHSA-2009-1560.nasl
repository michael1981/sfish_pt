
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42431);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1560: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1560");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.6.0-sun packages that correct several security issues are
  now available for Red Hat Enterprise Linux 4 Extras and 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The Sun 1.6.0 Java release includes the Sun Java 6 Runtime Environment and
  the Sun Java 6 Software Development Kit.

  This update fixes several vulnerabilities in the Sun Java 6 Runtime
  Environment and the Sun Java 6 Software Development Kit. These
  vulnerabilities are summarized on the "Advance notification of Security
  Updates for Java SE" page from Sun Microsystems, listed in the References
  section. (CVE-2009-2409, CVE-2009-3728, CVE-2009-3729, CVE-2009-3865,
  CVE-2009-3866, CVE-2009-3867, CVE-2009-3868, CVE-2009-3869, CVE-2009-3871,
  CVE-2009-3872, CVE-2009-3873, CVE-2009-3874, CVE-2009-3875, CVE-2009-3876,
  CVE-2009-3877, CVE-2009-3879, CVE-2009-3880, CVE-2009-3881, CVE-2009-3882,
  CVE-2009-3883, CVE-2009-3884, CVE-2009-3886)

  Users of java-1.6.0-sun should upgrade to these updated packages, which
  correct these issues. All running instances of Sun Java must be restarted
  for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1560.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2409", "CVE-2009-3728", "CVE-2009-3729", "CVE-2009-3865", "CVE-2009-3866", "CVE-2009-3867", "CVE-2009-3868", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3872", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884", "CVE-2009-3886");
script_summary(english: "Check for the version of the java packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"java-1.6.0-sun-1.6.0.17-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-demo-1.6.0.17-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-devel-1.6.0.17-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-jdbc-1.6.0.17-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-plugin-1.6.0.17-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-src-1.6.0.17-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-1.6.0.17-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-demo-1.6.0.17-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-devel-1.6.0.17-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-jdbc-1.6.0.17-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-plugin-1.6.0.17-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-src-1.6.0.17-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
