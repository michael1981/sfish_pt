
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40706);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2007-0829: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0829");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.5.0-ibm packages that correct several security issues are
  now available for Red Hat Enterprise Linux 4 Extras and 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  IBM\'s 1.5.0 Java release includes the IBM Java 2 Runtime Environment and
  the IBM Java 2 Software Development Kit.

  A security vulnerability in the Java Web Start component was discovered. An
  untrusted application could elevate it\'s privileges, allowing it to read
  and write local files that are accessible to the user running the Java Web
  Start application. (CVE-2007-2435)

  A buffer overflow in the Java Runtime Environment image handling code was
  found. An untrusted applet or application could use this flaw to elevate
  its privileges and potentially execute arbitrary code as the user running
  the java virtual machine. (CVE-2007-2788, CVE-2007-2789, CVE-2007-3004)

  An unspecified vulnerability was discovered in the Java Runtime
  Environment. An untrusted applet or application could cause the java
  virtual machine to become unresponsive. (CVE-2007-3005)

  The Javadoc tool was able to generate HTML documentation pages that
  contained cross-site scripting (XSS) vulnerabilities. A remote attacker
  could use this to inject arbitrary web script or HTML. (CVE-2007-3503)

  The Java Web Start URL parsing component contains a buffer overflow
  vulnerability within the parsing code for JNLP files. A remote attacker
  could create a malicious JNLP file that could trigger this flaw and execute
  arbitrary code when opened. (CVE-2007-3655)

  A flaw was found in the applet class loader. An untrusted applet could use
  this flaw to circumvent network access restrictions, possibly connecting
  to services hosted on the machine that executed the applet. (CVE-2007-3922)

  All users of java-ibm-1.5.0 should upgrade to these updated packages, which
  contain IBM\'s 1.5.0 SR5a Java release that resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0829.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2435", "CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3503", "CVE-2007-3655", "CVE-2007-3922", "CVE-2007-4381");
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

if ( rpm_check( reference:"java-1.5.0-ibm-1.5.0.5-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-demo-1.5.0.5-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-devel-1.5.0.5-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-javacomm-1.5.0.5-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-jdbc-1.5.0.5-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-plugin-1.5.0.5-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-src-1.5.0.5-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
