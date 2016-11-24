
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40709);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2007-0963: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0963");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.5.0-sun packages that correct several security issues are
  now available for Red Hat Enterprise Linux 4 Extras and 5 Supplementary.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Java Runtime Environment (JRE) contains the software and tools
  that users need to run applets and applications written using the Java
  programming language.

  A flaw in the applet caching mechanism of the Java Runtime Environment
  (JRE) did not correctly process the creation of network connections. A
  remote attacker could use this flaw to create connections to
  services on machines other than the one that the applet was downloaded
  from. (CVE-2007-5232)

  Multiple vulnerabilities existed in Java Web Start allowing an untrusted
  application to determine the location of the Java Web Start cache.
  (CVE-2007-5238)

  Untrusted Java Web Start Applications or Java Applets were able to drag and
  drop a file to a Desktop Application. A user-assisted remote attacker could
  use this flaw to move or copy arbitrary files. (CVE-2007-5239)

  The Java Runtime Environment (JRE) allowed untrusted Java Applets or
  applications to display oversized Windows. This could be used by remote
  attackers to hide security warning banners. (CVE-2007-5240)

  Unsigned Java Applets communicating via a HTTP proxy could allow a remote
  attacker to violate the Java security model. A cached, malicious Applet
  could create network connections to services on other machines.
  (CVE-2007-5273)

  Unsigned Applets loaded with Mozilla Firefox or Opera browsers allowed
  remote attackers to violate the Java security model. A cached, malicious
  Applet could create network connections to services on other machines.
  (CVE-2007-5274)

  In Red Hat Enterprise Linux a Java Web Start application requesting
  elevated permissions is only started automatically when signed with a
  trusted code signing certificate and otherwise requires user confirmation
  to access privileged resources.

  All users of java-sun-1.5.0 should upgrade to these packages, which contain
  Sun Java 1.5.0 Update 13 that corrects these issues.

  Please note that during our quality testing we discovered that the Java
  browser plug-in may not function perfectly when visiting some sites that
  make use of multiple applets on a single HTML page. We have verified that
  this issue is not due to our packaging and affects Sun Java 1.5.0 Update 13.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0963.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5232", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2007-5274", "CVE-2007-5689");
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

if ( rpm_check( reference:"java-1.5.0-sun-1.5.0.13-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-demo-1.5.0.13-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-devel-1.5.0.13-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-jdbc-1.5.0.13-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-plugin-1.5.0.13-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-sun-src-1.5.0.13-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
