
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40703);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2007-0167: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0167");
 script_set_attribute(attribute: "description", value: '
  java-1.5.0-ibm packages that correct a security issue are available for Red
  Hat Enterprise Linux 5 Supplementary and Enterprise Linux 4 Extras.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  IBM\'s 1.5.0 Java release includes the IBM Java 2 Runtime Environment and
  the IBM Java 2 Software Development Kit.

  A flaw in GIF image handling was found in the SUN Java Runtime Environment
  that has now been reported as also affecting IBM Java 2. An untrusted
  applet or application could use this flaw to elevate its privileges and
  potentially execute arbitrary code. (CVE-2007-0243)

  This update also resolves the following issues:

  * The java-1.5.0-ibm-plugin sub-package conflicted with the new
  java-1.5.0-sun-plugin sub-package.

  * The java-1.5.0-ibm-plugin package had incorrect dependencies. The
  java-1.5.0-ibm-alsa package has been merged into the java-1.5.0-ibm package
  to resolve this issue.

  All users of java-ibm-1.5.0 should upgrade to these packages, which contain
  IBM\'s 1.5.0 SR4 Java release which resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0167.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-0243");
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

if ( rpm_check( reference:"java-1.5.0-ibm-1.5.0.4-1jpp.3.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-demo-1.5.0.4-1jpp.3.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-devel-1.5.0.4-1jpp.3.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-javacomm-1.5.0.4-1jpp.3.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-jdbc-1.5.0.4-1jpp.3.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-plugin-1.5.0.4-1jpp.3.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-ibm-src-1.5.0.4-1jpp.3.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
