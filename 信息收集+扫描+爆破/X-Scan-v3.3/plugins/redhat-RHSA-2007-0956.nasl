
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40708);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2007-0956: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0956");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.5.0-bea packages that correct several security issues are
  now available for Red Hat Enterprise Linux 4 Extras and 5 Supplementary.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The BEA WebLogic JRockit 1.5.0_11 JRE and SDK contain BEA WebLogic JRockit
  Virtual Machine 1.5.0_11 and are certified for the Java 5 Platform,
  Standard Edition, v1.5.0.

  A flaw was found in the BEA Java Runtime Environment GIF image handling.
  If an application processes untrusted GIF image input, it may be possible
  to execute arbitrary code as the user running the Java Virtual Machine.
  (CVE-2007-0243)

  A buffer overflow in the Java Runtime Environment image handling code was
  found. If an attacker is able to cause a server application to process a
  specially crafted image file, it may be possible to execute arbitrary code
  as the user running the Java Virtual Machine. (CVE-2007-2788,
  CVE-2007-2789, CVE-2007-3004)

  A denial of service flaw was discovered in the Java Applet Viewer. An
  untrusted Java applet could cause the Java Virtual Machine to become
  unresponsive. Please note that the BEA WebLogic JRockit 1.5.0_11 does not
  ship with a browser plug-in and therefore this issue could only be
  triggered by a user running the "appletviewer" application. (CVE-2007-3005)

  A cross site scripting (XSS) flaw was found in the Javadoc tool. An
  attacker could inject arbitrary content into a Javadoc generated HTML
  documentation page, possibly tricking a user or stealing sensitive
  information. (CVE-2007-3503)

  A denial of service flaw was found in the way the JSSE component processed
  SSL/TLS handshake requests. A remote attacker able to connect to a JSSE
  enabled service could send a specially crafted handshake which would cause
  the Java Runtime Environment to stop responding to future requests.
  (CVE-2007-3698)

  A flaw was found in the way the Java Runtime Environment processes font
  data. An applet viewed via the \'appletviewer\' application could elevate
  its privileges, allowing the applet to perform actions with the same
  permissions as the user running the "appletviewer" application. It may also
  be possible to crash a server application which processes untrusted font
  information from a third party. (CVE-2007-4381)

  All users of java-bea-1.5.0 should upgrade to these updated packages, which
  contain the BEA WebLogic JRockit 1.5.0_11 release that resolves these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0956.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-0243", "CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3503", "CVE-2007-3698", "CVE-2007-4381");
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

if ( rpm_check( reference:"java-1.5.0-bea-1.5.0.11-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-demo-1.5.0.11-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-devel-1.5.0.11-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-jdbc-1.5.0.11-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-src-1.5.0.11-1jpp.2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
