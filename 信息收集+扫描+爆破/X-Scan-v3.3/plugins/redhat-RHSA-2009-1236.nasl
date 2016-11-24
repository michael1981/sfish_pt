
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40814);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1236: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1236");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.5.0-ibm packages that fix several security issues are now
  available for Red Hat Enterprise Linux 4 Extras and 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The IBM 1.5.0 Java release includes the IBM Java 2 Runtime Environment and
  the IBM Java 2 Software Development Kit.

  This update fixes several vulnerabilities in the IBM Java 2 Runtime
  Environment and the IBM Java 2 Software Development Kit. These
  vulnerabilities are summarized on the IBM "Security alerts" page listed in
  the References section. (CVE-2009-2625, CVE-2009-2670, CVE-2009-2671,
  CVE-2009-2672, CVE-2009-2673, CVE-2009-2675)

  All users of java-1.5.0-ibm are advised to upgrade to these updated
  packages, containing the IBM 1.5.0 SR10 Java release. All running instances
  of IBM Java must be restarted for this update to take effect.

  Note: The packages included in this update are identical to the packages
  made available by RHEA-2009:1208 and RHEA-2009:1210 on the 13th of
  August 2009. These packages are being reissued as a Red Hat Security
  Advisory as they fixed a number of security issues that were not made
  public until after those errata were released. Since the packages are
  identical, there is no need to install this update if RHEA-2009:1208 or
  RHEA-2009:1210 has already been installed.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1236.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2675");
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

if ( rpm_check( reference:"java-1.5.0-ibm-1.5.0.10-1jpp.4.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-demo-1.5.0.10-1jpp.4.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-devel-1.5.0.10-1jpp.4.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-javacomm-1.5.0.10-1jpp.4.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-jdbc-1.5.0.10-1jpp.4.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-plugin-1.5.0.10-1jpp.4.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-src-1.5.0.10-1jpp.4.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-1.5.0.10-1jpp.4.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-demo-1.5.0.10-1jpp.4.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-devel-1.5.0.10-1jpp.4.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-javacomm-1.5.0.10-1jpp.4.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-jdbc-1.5.0.10-1jpp.4.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-plugin-1.5.0.10-1jpp.4.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-src-1.5.0.10-1jpp.4.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
