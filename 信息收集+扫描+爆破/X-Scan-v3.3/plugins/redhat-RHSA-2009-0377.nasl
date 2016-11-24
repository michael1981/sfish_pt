
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36111);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2009-0377: java");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0377");
 script_set_attribute(attribute: "description", value: '
  Updated java-1.6.0-openjdk packages that fix several security issues are
  now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  These packages provide the OpenJDK 6 Java Runtime Environment and the
  OpenJDK 6 Software Development Kit. The Java Runtime Environment (JRE)
  contains the software and tools that users need to run applications written
  using the Java programming language.

  A flaw was found in the way that the Java Virtual Machine (JVM) handled
  temporary font files. A malicious applet could use this flaw to use large
  amounts of disk space, causing a denial of service. (CVE-2006-2426)

  A memory leak flaw was found in LittleCMS (embedded in OpenJDK). An
  application using color profiles could use excessive amounts of memory, and
  possibly crash after using all available memory, if used to open
  specially-crafted images. (CVE-2009-0581)

  Multiple integer overflow flaws which could lead to heap-based buffer
  overflows, as well as multiple insufficient input validation flaws, were
  found in the way LittleCMS handled color profiles. An attacker could use
  these flaws to create a specially-crafted image file which could cause a
  Java application to crash or, possibly, execute arbitrary code when opened.
  (CVE-2009-0723, CVE-2009-0733)

  A null pointer dereference flaw was found in LittleCMS. An application
  using color profiles could crash while converting a specially-crafted image
  file. (CVE-2009-0793)

  A flaw in the Java API for XML Web Services (JAX-WS) service endpoint
  handling could allow a remote attacker to cause a denial of service on the
  server application hosting the JAX-WS service endpoint. (CVE-2009-1101)

  A flaw in the way the Java Runtime Environment initialized LDAP connections
  could allow a remote, authenticated user to cause a denial of service on
  the LDAP service. (CVE-2009-1093)

  A flaw in the Java Runtime Environment LDAP client could allow malicious
  data from an LDAP server to cause arbitrary code to be loaded and then run
  on an LDAP client. (CVE-2009-1094)

  Several buffer overflow flaws were found in the Java Runtime Environment
  unpack200 functionality. An untrusted applet could extend its privileges,
  allowing it to read and write local files, as well as to execute local
  applications with the privileges of the user running the applet.
  (CVE-2009-1095, CVE-2009-1096)

  A flaw in the Java Runtime Environment Virtual Machine code generation
  functionality could allow untrusted applets to extend their privileges. An
  untrusted applet could extend its privileges, allowing it to read and write
  local files, as well as execute local applications with the privileges
  of the user running the applet. (CVE-2009-1102)

  A buffer overflow flaw was found in the splash screen processing. A remote
  attacker could extend privileges to read and write local files, as well as
  to execute local applications with the privileges of the user running the
  java process. (CVE-2009-1097)

  A buffer overflow flaw was found in how GIF images were processed. A remote
  attacker could extend privileges to read and write local files, as well as
  execute local applications with the privileges of the user running the
  java process. (CVE-2009-1098)

  Note: The flaws concerning applets in this advisory, CVE-2009-1095,
  CVE-2009-1096, and CVE-2009-1102, can only be triggered in
  java-1.6.0-openjdk by calling the "appletviewer" application.

  All users of java-1.6.0-openjdk are advised to upgrade to these updated
  packages, which resolve these issues. All running instances of OpenJDK Java
  must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0377.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-2426", "CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733", "CVE-2009-0793", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1101", "CVE-2009-1102");
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

if ( rpm_check( reference:"java-1.6.0-openjdk-1.6.0.0-0.30.b09.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-demo-1.6.0.0-0.30.b09.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-devel-1.6.0.0-0.30.b09.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-0.30.b09.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-src-1.6.0.0-0.30.b09.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
