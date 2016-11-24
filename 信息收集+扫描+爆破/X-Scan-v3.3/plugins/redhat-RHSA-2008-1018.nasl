
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40731);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2008-1018: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-1018");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.6.0-sun packages that correct several security issues are
  now available for Red Hat Enterprise Linux 4 Extras and 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The Java Runtime Environment (JRE) contains the software and tools that
  users need to run applets and applications written using the Java
  programming language.

  A vulnerability was found in in Java Web Start. If a user visits a
  malicious website, an attacker could misuse this flaw to execute arbitrary
  code. (CVE-2008-2086)

  Additionally, these packages fix several other critical vulnerabilities.
  These are summarized in the "Advance notification of Security Updates for
  Java SE" from Sun Microsystems.

  Users of java-1.6.0-sun should upgrade to these updated packages, which
  correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-1018.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2086", "CVE-2008-5339", "CVE-2008-5340", "CVE-2008-5341", "CVE-2008-5342", "CVE-2008-5343", "CVE-2008-5344", "CVE-2008-5345", "CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5356", "CVE-2008-5357", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360");
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

if ( rpm_check( reference:"java-1.6.0-sun-1.6.0.11-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-demo-1.6.0.11-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-devel-1.6.0.11-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-jdbc-1.6.0.11-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-plugin-1.6.0.11-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-src-1.6.0.11-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-1.6.0.11-1jpp.1.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-demo-1.6.0.11-1jpp.1.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-devel-1.6.0.11-1jpp.1.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-jdbc-1.6.0.11-1jpp.1.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-plugin-1.6.0.11-1jpp.1.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-sun-src-1.6.0.11-1jpp.1.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
