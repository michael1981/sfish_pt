
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40734);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2008-1044: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-1044");
 script_set_attribute(attribute: "description", value: '
  java-1.5.0-bea as shipped in Red Hat Enterprise Linux 4 Extras and Red Hat
  Enterprise Linux 5 Supplementary, contains security flaws and should not be
  used.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The BEA WebLogic JRockit JRE and SDK contains BEA WebLogic JRockit Virtual
  Machine and is certified for the Java™ 2 Platform, Standard Edition,
  v1.5.0.

  The java-1.5.0-bea packages are vulnerable to important security flaws and
  should no longer be used.

  A flaw was found in the Java Management Extensions (JMX) management agent.
  When local monitoring was enabled, remote attackers could use this flaw to
  perform illegal operations. (CVE-2008-3103)

  Several flaws involving the handling of unsigned applets were found. A
  remote attacker could misuse an unsigned applet in order to connect to
  services on the host running the applet. (CVE-2008-3104)

  Several flaws in the Java API for XML Web Services (JAX-WS) client and the
  JAX-WS service implementation were found. A remote attacker who could cause
  malicious XML to be processed by an application could access URLs, or cause
  a denial of service. (CVE-2008-3105, CVE-2008-3106)

  A buffer overflow vulnerability was found in the font processing code. This
  allowed remote attackers to extend the permissions of an untrusted applet
  or application, allowing it to read or write local files, as well as to
  execute local applications accessible to the user running the untrusted
  application. (CVE-2008-3108)

  The vulnerabilities concerning applets listed above can only be triggered
  in java-1.5.0-bea, by calling the "appletviewer" application.

  BEA was acquired by Oracle® during 2008 (the acquisition was completed on
  April 29, 2008). Consequently, JRockit is now an Oracle offering and these
  issues are addressed in the current release of Oracle JRockit. Due to a
  license change by Oracle, however, Red Hat is unable to ship Oracle
  JRockit.

  Users who wish to continue using JRockit should get an update directly from
  Oracle: http://oracle.com/technology/software/products/jrockit/.

  Alternatives to Oracle JRockit include the Java 2 Technology Edition of the
  IBM® Developer Kit for Linux and the Sun™ Java SE Development Kit (JDK),
  both of which are available on the Extras or Supplementary channels. For
  Java 6 users, the new OpenJDK open source JDK will be included in Red Hat
  Enterprise Linux 5.3 and will be supported by Red Hat.

  This update removes the java-1.5.0-bea packages due to their known security
  vulnerabilities.


');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-1044.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

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

if ( rpm_check( reference:"java-1.5.0-bea-uninstall-1.5.0.14-1jpp.5.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.5.0-bea-uninstall-1.5.0.14-1jpp.5.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
