
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40712);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2008-0100: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0100");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.4.2-bea packages that correct several security issues and
  add enhancements are now available for Red Hat Enterprise Linux 3 Extras,
  Red Hat Enterprise Linux 4 Extras, and Red Hat Enterprise Linux 5
  Supplementary.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The BEA WebLogic JRockit 1.4.2_16 JRE and SDK contains BEA WebLogic JRockit
  Virtual Machine 1.4.2_16 and is certified for the Java 2 Platform, Standard
  Edition, v1.4.2.

  A buffer overflow in the Java Runtime Environment image handling code was
  found. If an attacker could induce a server application to process a
  specially crafted image file, the attacker could potentially cause a
  denial-of-service or execute arbitrary code as the user running the Java
  Virtual Machine. (CVE-2007-2788, CVE-2007-2789)

  A denial of service flaw was found in the way the JSSE component processed
  SSL/TLS handshake requests. A remote attacker able to connect to a JSSE
  enabled service could send a specially crafted handshake which would cause
  the Java Runtime Environment to stop responding to future requests.
  (CVE-2007-3698)

  A flaw was found in the way the Java Runtime Environment processed font
  data. An applet viewed via the "appletviewer" application could elevate its
  privileges, allowing the applet to perform actions with the same
  permissions as the user running the "appletviewer" application. The same
  flaw could, potentially, crash a server application which processed
  untrusted font information from a third party. (CVE-2007-4381)

  A flaw in the applet caching mechanism of the Java Runtime Environment
  (JRE) did not correctly process the creation of network connections. A
  remote attacker could use this flaw to create connections to services on
  machines other than the one that the applet was downloaded from.
  (CVE-2007-5232)

  Untrusted Java Applets were able to drag and drop files to a desktop
  application. A user-assisted remote attacker could use this flaw to move or
  copy arbitrary files. (CVE-2007-5239)

  The Java Runtime Environment (JRE) allowed untrusted Java Applets or
  applications to display over-sized windows. This could be used by remote
  attackers to hide security warning banners. (CVE-2007-5240)

  Unsigned Java Applets communicating via a HTTP proxy could allow a remote
  attacker to violate the Java security model. A cached, malicious Applet
  could create network connections to services on other machines.
  (CVE-2007-5273)

  Please note: the vulnerabilities noted above concerned with applets can
  only be triggered in java-1.4.2-bea by calling the "appletviewer"
  application.

  All users of java-1.4.2-bea should upgrade to these updated packages, which
  contain the BEA WebLogic JRockit 1.4.2_16 release which resolves these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0100.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3698", "CVE-2007-4381", "CVE-2007-5232", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273");
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

if ( rpm_check( reference:"java-1.4.2-bea-1.4.2.16-1jpp.1.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-bea-devel-1.4.2.16-1jpp.1.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-bea-jdbc-1.4.2.16-1jpp.1.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-bea-1.4.2.16-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-bea-devel-1.4.2.16-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-bea-jdbc-1.4.2.16-1jpp.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-bea-1.4.2.16-1jpp.1.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-bea-devel-1.4.2.16-1jpp.1.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.4.2-bea-jdbc-1.4.2.16-1jpp.1.el4", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
