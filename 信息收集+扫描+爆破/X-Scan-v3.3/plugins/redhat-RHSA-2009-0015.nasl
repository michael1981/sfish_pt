
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40737);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-0015: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0015");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.6.0-ibm packages that fix several security issues are now
  available for Red Hat Enterprise Linux 4 Extras and 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The IBM 1.6.0 Java release includes the IBM Java 2 Runtime Environment and
  the IBM Java 2 Software Development Kit.

  This update fixes several vulnerabilities in the IBM Java 2 Runtime
  Environment and the IBM Java 2 Software Development Kit. These are
  summarized in the "Security Alerts" from IBM.

  All users of java-1.6.0-ibm are advised to upgrade to these updated
  packages, containing the IBM 1.6.0 SR3 Java release.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0015.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2086", "CVE-2008-5339", "CVE-2008-5344", "CVE-2008-5345", "CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5350", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5359", "CVE-2008-5360");
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

if ( rpm_check( reference:"java-1.6.0-ibm-1.6.0.3-1jpp.3.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-demo-1.6.0.3-1jpp.3.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-devel-1.6.0.3-1jpp.3.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-javacomm-1.6.0.3-1jpp.3.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-jdbc-1.6.0.3-1jpp.3.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-plugin-1.6.0.3-1jpp.3.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-src-1.6.0.3-1jpp.3.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-1.6.0.3-1jpp.3.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-demo-1.6.0.3-1jpp.3.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-devel-1.6.0.3-1jpp.3.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-javacomm-1.6.0.3-1jpp.3.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-jdbc-1.6.0.3-1jpp.3.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-plugin-1.6.0.3-1jpp.3.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-src-1.6.0.3-1jpp.3.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
