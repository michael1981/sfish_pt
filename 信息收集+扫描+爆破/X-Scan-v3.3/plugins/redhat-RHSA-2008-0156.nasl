
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40716);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2008-0156: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0156");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.5.0-bea packages that correct several security issues are
  now available for Red Hat Enterprise Linux 4 Extras and 5 Supplementary.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The BEA WebLogic JRockit 1.5.0_14 JRE and SDK contain BEA WebLogic JRockit
  Virtual Machine 1.5.0_14 and are certified for the Java 5 Platform,
  Standard Edition, v1.5.0.

  A flaw in the applet caching mechanism of the Java Runtime Environment
  (JRE) did not correctly process the creation of network connections. A
  remote attacker could use this flaw to create connections to services on
  machines other than the one that the applet was downloaded from.
  (CVE-2007-5232)

  Untrusted Java Applets were able to drag and drop a file to a Desktop
  Application. A user-assisted remote attacker could use this flaw to move or
  copy arbitrary files. (CVE-2007-5239)

  The Java Runtime Environment (JRE) allowed untrusted Java Applets or
  applications to display oversized windows. This could be used by remote
  attackers to hide security warning banners. (CVE-2007-5240)

  Unsigned Java Applets communicating via a HTTP proxy could allow a remote
  attacker to violate the Java security model. A cached, malicious Applet
  could create network connections to services on other machines. (CVE-2007-5273)

  Two vulnerabilities in the Java Runtime Environment allowed an untrusted
  application or applet to elevate the assigned privileges. This could be
  misused by a malicious website to read and write local files or execute
  local applications in the context of the user running the Java process.
  (CVE-2008-0657)

  Those vulnerabilities concerned with applets can only be triggered in
  java-1.5.0-bea by calling the \'appletviewer\' application.

  All users of java-1.5.0-bea should upgrade to these updated packages, which
  contain the BEA WebLogic JRockit 1.5.0_14 release that resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0156.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5232", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2008-0657");
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

if ( rpm_check( reference:"java-1.5.0-bea-1.5.0.14-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-demo-1.5.0.14-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-devel-1.5.0.14-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-jdbc-1.5.0.14-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-src-1.5.0.14-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-1.5.0.14-1jpp.1.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-demo-1.5.0.14-1jpp.1.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-devel-1.5.0.14-1jpp.1.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-jdbc-1.5.0.14-1jpp.1.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-src-1.5.0.14-1jpp.1.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
