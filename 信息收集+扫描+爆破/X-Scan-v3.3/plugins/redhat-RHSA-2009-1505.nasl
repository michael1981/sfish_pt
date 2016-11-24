
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42135);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1505: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1505");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.4.2-ibm packages that fix two security issues are now
  available for Red Hat Enterprise Linux 3 Extras, Red Hat Enterprise Linux 4
  Extras, and Red Hat Enterprise Linux 5 Supplementary.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The IBM 1.4.2 SR13-FP1 Java release includes the IBM Java 2 Runtime
  Environment and the IBM Java 2 Software Development Kit.

  This update fixes two vulnerabilities in the IBM Java 2 Runtime Environment
  and the IBM Java 2 Software Development Kit. These vulnerabilities are
  summarized on the IBM "Security alerts" page listed in the References
  section. (CVE-2008-5349, CVE-2009-2625)

  All users of java-1.4.2-ibm are advised to upgrade to these updated
  packages, which contain the IBM 1.4.2 SR13-FP1 Java release. All running
  instances of IBM Java must be restarted for this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1505.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-5349", "CVE-2009-2625");
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

if ( rpm_check( reference:"java-1.4.2-ibm-1.4.2.13.1-1jpp.1.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-demo-1.4.2.13.1-1jpp.1.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-devel-1.4.2.13.1-1jpp.1.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-jdbc-1.4.2.13.1-1jpp.1.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-plugin-1.4.2.13.1-1jpp.1.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-src-1.4.2.13.1-1jpp.1.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-1.4.2.13.1-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-demo-1.4.2.13.1-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-devel-1.4.2.13.1-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-javacomm-1.4.2.13.1-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-jdbc-1.4.2.13.1-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-plugin-1.4.2.13.1-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-src-1.4.2.13.1-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-1.4.2.13.1-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-demo-1.4.2.13.1-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-devel-1.4.2.13.1-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-javacomm-1.4.2.13.1-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-jdbc-1.4.2.13.1-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-plugin-1.4.2.13.1-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-src-1.4.2.13.1-1jpp.1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
