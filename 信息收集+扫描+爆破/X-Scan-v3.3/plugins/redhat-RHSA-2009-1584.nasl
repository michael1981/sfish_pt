
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42828);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1584: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1584");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.6.0-openjdk packages that fix several security issues are
  now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  These packages provide the OpenJDK 6 Java Runtime Environment and the
  OpenJDK 6 Software Development Kit. The Java Runtime Environment (JRE)
  contains the software and tools that users need to run applications written
  using the Java programming language.

  An integer overflow flaw and buffer overflow flaws were found in the way
  the JRE processed image files. An untrusted applet or application could use
  these flaws to extend its privileges, allowing it to read and write local
  files, as well as to execute local applications with the privileges of the
  user running the applet or application. (CVE-2009-3869, CVE-2009-3871,
  CVE-2009-3873, CVE-2009-3874)

  An information leak was found in the JRE. An untrusted applet or
  application could use this flaw to extend its privileges, allowing it to
  read and write local files, as well as to execute local applications with
  the privileges of the user running the applet or application. (CVE-2009-3881)

  It was discovered that the JRE still accepts certificates with MD2 hash
  signatures, even though MD2 is no longer considered a cryptographically
  strong algorithm. This could make it easier for an attacker to create a
  malicious certificate that would be treated as trusted by the JRE. With
  this update, the JRE disables the use of the MD2 algorithm inside
  signatures by default. (CVE-2009-2409)

  A timing attack flaw was found in the way the JRE processed HMAC digests.
  This flaw could aid an attacker using forged digital signatures to bypass
  authentication checks. (CVE-2009-3875)

  Two denial of service flaws were found in the JRE. These could be exploited
  in server-side application scenarios that process DER-encoded
  (Distinguished Encoding Rules) data. (CVE-2009-3876, CVE-2009-3877)

  An information leak was found in the way the JRE handled color profiles. An
  attacker could use this flaw to discover the existence of files outside of
  the color profiles directory. (CVE-2009-3728)

  A flaw in the JRE with passing arrays to the X11GraphicsDevice API was
  found. An untrusted applet or application could use this flaw to access and
  modify the list of supported graphics configurations. This flaw could also
  lead to sensitive information being leaked to unprivileged code.
  (CVE-2009-3879)

  It was discovered that the JRE passed entire objects to the logging API.
  This could lead to sensitive information being leaked to either untrusted
  or lower-privileged code from an attacker-controlled applet which has
  access to the logging API and is therefore able to manipulate (read and/or
  call) the passed objects. (CVE-2009-3880)

  Potential information leaks were found in various mutable static variables.
  These could be exploited in application scenarios that execute untrusted
  scripting code. (CVE-2009-3882, CVE-2009-3883)

  An information leak was found in the way the TimeZone.getTimeZone method
  was handled. This method could load time zone files that are outside of the
  [JRE_HOME]/lib/zi/ directory, allowing a remote attacker to probe the local
  file system. (CVE-2009-3884)

  Note: The flaws concerning applets in this advisory, CVE-2009-3869,
  CVE-2009-3871, CVE-2009-3873, CVE-2009-3874, CVE-2009-3879, CVE-2009-3880,
  CVE-2009-3881 and CVE-2009-3884, can only be triggered in
  java-1.6.0-openjdk by calling the "appletviewer" application.

  All users of java-1.6.0-openjdk are advised to upgrade to these updated
  packages, which resolve these issues. All running instances of OpenJDK Java
  must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1584.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2409", "CVE-2009-3728", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884");
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

if ( rpm_check( reference:"java-1.6.0-openjdk-1.6.0.0-1.7.b09.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.7.b09.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.7.b09.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.7.b09.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-src-1.6.0.0-1.7.b09.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-1.6.0.0-1.7.b09.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.7.b09.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.7.b09.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.7.b09.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-src-1.6.0.0-1.7.b09.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
