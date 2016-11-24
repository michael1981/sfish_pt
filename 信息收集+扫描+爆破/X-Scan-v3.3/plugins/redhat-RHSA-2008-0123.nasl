
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40713);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2008-0123: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0123");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.5.0-sun packages that correct several security issues are
  now available for Red Hat Enterprise Linux 4 Extras and 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The Java Runtime Environment (JRE) contains the software and tools that
  users need to run applets and applications written using the Java
  programming language.

  These updated java-1.5.0-sun packages resolve the following security issues:

  Two vulnerabilities in the Java Runtime Environment allowed an untrusted
  application or applet to elevate the assigned privileges. This could be
  misused by a malicious website to read and write local files or execute
  local applications in the context of the user running the Java process.
  (CVE-2008-0657)

  Users of java-1.5.0-sun should upgrade to these updated packages, which
  contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0123.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-0657");
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

if ( rpm_check( reference:"java-1.5.0-sun-1.5.0.14-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-demo-1.5.0.14-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-devel-1.5.0.14-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-jdbc-1.5.0.14-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-plugin-1.5.0.14-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-src-1.5.0.14-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-1.5.0.14-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-demo-1.5.0.14-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-devel-1.5.0.14-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-jdbc-1.5.0.14-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-plugin-1.5.0.14-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-src-1.5.0.14-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
