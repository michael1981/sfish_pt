
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40717);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2008-0186: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0186");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.5.0-sun packages that correct several security issues are
  now available for Red Hat Enterprise Linux 4 Extras and 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The Java Runtime Environment (JRE) contains the software and tools
  that users need to run applets and applications written using the Java
  programming language.

  Flaws in the JRE allowed an untrusted application or applet to elevate its
  privileges. This could be exploited by a remote attacker to access local
  files or execute local applications accessible to the user running the JRE
  (CVE-2008-1185, CVE-2008-1186)

  A flaw was found in the Java XSLT processing classes. An untrusted
  application or applet could cause a denial of service, or execute arbitrary
  code with the permissions of the user running the JRE. (CVE-2008-1187)

  Several buffer overflow flaws were found in Java Web Start (JWS). An
  untrusted JNLP application could access local files or execute local
  applications accessible to the user running the JRE.
  (CVE-2008-1188, CVE-2008-1189, CVE-2008-1190, CVE-2008-1191, CVE-2008-1196)

  A flaw was found in the Java Plug-in. A remote attacker could bypass the
  same origin policy, executing arbitrary code with the permissions of the
  user running the JRE. (CVE-2008-1192)

  A flaw was found in the JRE image parsing libraries. An untrusted
  application or applet could cause a denial of service, or possible execute
  arbitrary code with the permissions of the user running the JRE.
  (CVE-2008-1193)

  A flaw was found in the JRE color management library. An untrusted
  application or applet could trigger a denial of service (JVM crash).
  (CVE-2008-1194)

  The JRE allowed untrusted JavaScript code to create local network
  connections by the use of Java APIs. A remote attacker could use these
  flaws to acesss local network services. (CVE-2008-1195)

  This update also fixes an issue where the Java Plug-in is not available for
  browser use after successful installation.

  Users of java-1.5.0-sun should upgrade to these updated packages, which
  correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0186.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1192", "CVE-2008-1193", "CVE-2008-1194", "CVE-2008-1195", "CVE-2008-1196");
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

if ( rpm_check( reference:"java-1.5.0-sun-1.5.0.15-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-demo-1.5.0.15-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-devel-1.5.0.15-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-jdbc-1.5.0.15-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-plugin-1.5.0.15-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-src-1.5.0.15-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-1.5.0.15-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-demo-1.5.0.15-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-devel-1.5.0.15-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-jdbc-1.5.0.15-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-plugin-1.5.0.15-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-src-1.5.0.15-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
