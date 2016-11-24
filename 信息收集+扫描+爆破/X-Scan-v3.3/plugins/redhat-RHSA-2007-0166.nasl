
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40702);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2007-0166: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0166");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.4.2-ibm packages to correct a security issue are now
  available for Red Hat Enterprise Linux 3 and 4 Extras.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  IBM\'s 1.4.2 SR8 Java release includes the IBM Java 2 Runtime Environment
  and the IBM Java 2 Software Development Kit.

  A flaw in GIF image handling was found in the SUN Java Runtime Environment
  that has now been reported as also affecting IBM Java 2. An untrusted
  applet or application could use this flaw to elevate its privileges and
  potentially execute arbitrary code. (CVE-2007-0243)

  All users of java-1.4.2-ibm should upgrade to these updated packages, which
  contain IBM\'s 1.4.2 SR8 Java release which resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0166.html");
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

if ( rpm_check( reference:"java-1.4.2-ibm-1.4.2.8-1jpp.1.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-demo-1.4.2.8-1jpp.1.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-devel-1.4.2.8-1jpp.1.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-jdbc-1.4.2.8-1jpp.1.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-plugin-1.4.2.8-1jpp.1.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-src-1.4.2.8-1jpp.1.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-1.4.2.8-1jpp.1.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-demo-1.4.2.8-1jpp.1.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-devel-1.4.2.8-1jpp.1.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-javacomm-1.4.2.8-1jpp.1.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-jdbc-1.4.2.8-1jpp.1.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-plugin-1.4.2.8-1jpp.1.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-ibm-src-1.4.2.8-1jpp.1.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
