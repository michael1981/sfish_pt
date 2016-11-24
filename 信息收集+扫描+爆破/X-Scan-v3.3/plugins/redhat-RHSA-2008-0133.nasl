
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33247);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2008-0133: IBMJava");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0133");
 script_set_attribute(attribute: "description", value: '
  IBMJava2-JRE and IBMJava2-SDK packages that correct several security issues
  are available for Red Hat Enterprise Linux 2.1.

  IBM\'s 1.3.1 Java release includes the IBM Java 2 Runtime Environment and
  the IBM Java 2 Software Development Kit.

  A buffer overflow was found in the Java Runtime Environment image-handling
  code. An untrusted applet or application could use this flaw to elevate its
  privileges and potentially execute arbitrary code as the user running the
  java virtual machine. (CVE-2007-3004)

  An unspecified vulnerability was discovered in the Java Runtime
  Environment. An untrusted applet or application could cause the java
  virtual machine to become unresponsive. (CVE-2007-3005)

  A flaw was found in the applet class loader. An untrusted applet could use
  this flaw to circumvent network access restrictions, possibly connecting to
  services hosted on the machine that executed the applet. (CVE-2007-3922)

  These updated packages also add the following enhancements:

  * Time zone information has been updated to the latest available
  information, 2007h.

  * Accessibility support in AWT can now be disabled through a system
  property, java.assistive. To support this change, permission to read this
  property must be added to /opt/IBMJava2-131/jre/lib/security/java.policy.
  Users of IBMJava2 who have modified this file should add this following
  line to the grant section:

  permission java.util.PropertyPermission "java.assistive", "read";

  All users of IBMJava2 should upgrade to these updated packages, which
  contain IBM\'s 1.3.1 SR11 Java release, which resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0133.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

 script_cve_id("CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3922");
script_summary(english: "Check for the version of the IBMJava packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"IBMJava2-JRE-1.3.1-17", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"IBMJava2-SDK-1.3.1-17", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"IBMJava2-JRE-1.3.1-17", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"IBMJava2-SDK-1.3.1-17", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
