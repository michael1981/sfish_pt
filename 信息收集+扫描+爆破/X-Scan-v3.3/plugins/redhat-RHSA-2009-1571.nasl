
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42455);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1571: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1571");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.5.0-sun packages that correct several security issues are
  now available for Red Hat Enterprise Linux 4 Extras and 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The Sun 1.5.0 Java release includes the Sun Java 5 Runtime Environment and
  the Sun Java 5 Software Development Kit.

  This update fixes several vulnerabilities in the Sun Java 5 Runtime
  Environment and the Sun Java 5 Software Development Kit. These
  vulnerabilities are summarized on the "Advance notification of Security
  Updates for Java SE" page from Sun Microsystems, listed in the References
  section. (CVE-2009-2409, CVE-2009-3728, CVE-2009-3873, CVE-2009-3876,
  CVE-2009-3877, CVE-2009-3879, CVE-2009-3880, CVE-2009-3881, CVE-2009-3882,
  CVE-2009-3883, CVE-2009-3884)

  Note: This is the final update for the java-1.5.0-sun packages, as the Sun
  Java SE Release family 5.0 has now reached End of Service Life. The next
  update will remove the java-1.5.0-sun packages.

  An alternative to Sun Java SE 5.0 is the Java 2 Technology Edition of the
  IBM Developer Kit for Linux, which is available from the Extras and
  Supplementary channels on the Red Hat Network. For users of applications
  that are capable of using the Java 6 runtime, the OpenJDK open source JDK
  is included in Red Hat Enterprise Linux 5 (since 5.3) and is supported by
  Red Hat.

  Users of java-1.5.0-sun should upgrade to these updated packages, which
  correct these issues. All running instances of Sun Java must be restarted
  for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1571.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2409", "CVE-2009-3728", "CVE-2009-3873", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884");
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

if ( rpm_check( reference:"java-1.5.0-sun-1.5.0.22-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-demo-1.5.0.22-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-devel-1.5.0.22-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-jdbc-1.5.0.22-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-plugin-1.5.0.22-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-src-1.5.0.22-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-1.5.0.22-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-demo-1.5.0.22-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-devel-1.5.0.22-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-jdbc-1.5.0.22-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-plugin-1.5.0.22-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-src-1.5.0.22-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
