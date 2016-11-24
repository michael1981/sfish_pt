
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40721);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2008-0244: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0244");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.5.0-bea packages that correct several security issues are
  now available for Red Hat Enterprise Linux 4 Extras and 5 Supplementary.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The BEA WebLogic JRockit 1.5.0_14 JRE and SDK contain BEA WebLogic JRockit
  Virtual Machine 1.5.0_14, and are certified for the Java 5 Platform,
  Standard Edition, v1.5.0.

  A flaw was found in the Java XSLT processing classes. An untrusted
  application or applet could cause a denial of service, or execute arbitrary
  code with the permissions of the user running the JRE. (CVE-2008-1187)

  A flaw was found in the JRE image parsing libraries. An untrusted
  application or applet could cause a denial of service, or possibly execute
  arbitrary code with the permissions of the user running the JRE.
  (CVE-2008-1193)

  A flaw was found in the JRE color management library. An untrusted
  application or applet could trigger a denial of service (JVM crash).
  (CVE-2008-1194)

  The vulnerabilities concerning applets listed above can only be triggered
  in java-1.5.0-bea, by calling the "appletviewer" application.

  Users of java-1.5.0-bea are advised to upgrade to these updated packages,
  which resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0244.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1187", "CVE-2008-1193", "CVE-2008-1194");
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

if ( rpm_check( reference:"java-1.5.0-bea-1.5.0.14-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-demo-1.5.0.14-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-devel-1.5.0.14-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-jdbc-1.5.0.14-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-src-1.5.0.14-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-1.5.0.14-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-demo-1.5.0.14-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-devel-1.5.0.14-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-jdbc-1.5.0.14-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-src-1.5.0.14-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
