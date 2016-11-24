
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24320);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0072: IBMJava");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0072");
 script_set_attribute(attribute: "description", value: '
  IBMJava2-JRE and IBMJava2-SDK packages that correct several security issues
  are available for Red Hat Enterprise Linux 2.1.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  IBM\'s 1.3.1 Java release includes the IBM Java 2 Runtime Environment
  and the IBM Java 2 Software Development Kit.

  Vulnerabilities were discovered in the Java Runtime Environment. An
  untrusted applet could use these vulnerabilities to access data from other
  applets. (CVE-2006-6736, CVE-2006-6737)

  Buffer overflow vulnerabilities were discovered in the Java Runtime
  Environment. An untrusted applet could use these flaws to elevate its
  privileges, possibly reading and writing local files or executing local
  applications. (CVE-2006-6731)

  Daniel Bleichenbacher discovered an attack on PKCS #1 v1.5 signatures.
  Where an RSA key with exponent 3 is used it may be possible for an attacker
  to forge a PKCS #1 v1.5 signature that would be incorrectly verified by
  implementations that do not check for excess data in the RSA exponentiation
  result of the signature. (CVE-2006-4339)

  All users of IBMJava2 should upgrade to these updated packages, which
  contain IBM\'s 1.3.1 SR10a Java release which resolves these issues.

  Please note that the packages in this erratum are the same as those we
  released on January 24th 2007 with advisories RHBA-2007:0023 and
  RHEA-2007:0024. We have issued this security update as these previous
  advisories did not specify that they fixed critical security issues. If
  you have already updated to those versions of IBMJava you will not need to
  apply this update.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0072.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4339", "CVE-2006-6731", "CVE-2006-6736", "CVE-2006-6737", "CVE-2007-0243");
script_summary(english: "Check for the version of the IBMJava packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"IBMJava2-JRE-1.3.1-12", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"IBMJava2-SDK-1.3.1-11", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
