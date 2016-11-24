
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40728);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2008-0906: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0906");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.6.0-ibm packages that fix several security issues are now
  available for Red Hat Enterprise Linux 4 Extras and Red Hat Enterprise
  Linux 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The IBM 1.6.0 Java release includes the IBM Java 2 Runtime Environment and
  the IBM Java 2 Software Development Kit.

  A flaw was found in the Java Management Extensions (JMX) management agent.
  When local monitoring is enabled, remote attackers could use this flaw to
  perform illegal operations. (CVE-2008-3103)

  Several flaws involving the handling of unsigned applets were found. A
  remote attacker could misuse an unsigned applet in order to connect to
  services on the host running the applet. (CVE-2008-3104)

  Several flaws in the Java API for XML Web Services (JAX-WS) client and the
  JAX-WS service implementation were found. A remote attacker who could cause
  malicious XML to be processed by an application could access URLs, or cause
  a denial of service. (CVE-2008-3105, CVE-2008-3106)

  Several flaws within the Java Runtime Environment (JRE) scripting support
  were found. A remote attacker could grant an untrusted applet extended
  privileges, such as reading and writing local files, executing
  local programs, or querying the sensitive data of other applets.
  (CVE-2008-3109, CVE-2008-3110)

  A flaw in Java Web Start was found. Using an untrusted Java Web
  Start application, a remote attacker could create or delete arbitrary
  files with the permissions of the user running the untrusted application.
  (CVE-2008-3112)

  A flaw in Java Web Start when processing untrusted applications was found.
  An attacker could use this flaw to acquire sensitive information, such as
  the location of the cache. (CVE-2008-3114)

  All users of java-1.6.0-ibm are advised to upgrade to these updated
  packages, containing the IBM 1.6.0 SR2 Java release, which resolves these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0906.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-3103", "CVE-2008-3104", "CVE-2008-3105", "CVE-2008-3106", "CVE-2008-3109", "CVE-2008-3110", "CVE-2008-3112", "CVE-2008-3114");
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

if ( rpm_check( reference:"java-1.6.0-ibm-1.6.0.2-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-demo-1.6.0.2-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-devel-1.6.0.2-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-javacomm-1.6.0.2-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-jdbc-1.6.0.2-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-plugin-1.6.0.2-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-src-1.6.0.2-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-1.6.0.2-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-demo-1.6.0.2-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-devel-1.6.0.2-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-javacomm-1.6.0.2-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-jdbc-1.6.0.2-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-plugin-1.6.0.2-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-ibm-src-1.6.0.2-1jpp.2.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
