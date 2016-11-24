
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16146);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-013: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-013");
 script_set_attribute(attribute: "description", value: '
  Updated CUPS packages that fix several security issues are now available.

  The Common UNIX Printing System provides a portable printing layer for
  UNIX(R) operating systems.

  A buffer overflow was found in the CUPS pdftops filter, which uses code
  from the Xpdf package. An attacker who has the ability to send a malicious
  PDF file to a printer could possibly execute arbitrary code as the "lp"
  user. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2004-1125 to this issue.

  A buffer overflow was found in the ParseCommand function in the hpgltops
  program. An attacker who has the ability to send a malicious HPGL file to a
  printer could possibly execute arbitrary code as the "lp" user. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-1267 to this issue.

  Red Hat believes that the Exec-Shield technology (enabled by default since
  Update 3) will block attempts to exploit these buffer overflow
  vulnerabilities on x86 architectures.

  The lppasswd utility ignores write errors when modifying the CUPS passwd
  file. A local user who is able to fill the associated file system could
  corrupt the CUPS password file or prevent future uses of lppasswd. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the names CAN-2004-1268 and CAN-2004-1269 to these issues.

  The lppasswd utility does not verify that the passwd.new file is different
  from STDERR, which could allow local users to control output to passwd.new
  via certain user input that triggers an error message. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-1270 to this issue.

  In addition to these security issues, two other problems not relating
  to security have been fixed:

  Resuming a job with "lp -H resume", which had previously been held with "lp
  -H hold" could cause the scheduler to stop. This has been fixed in later
  versions of CUPS, and has been backported in these updated packages.

  The cancel-cups(1) man page is a symbolic link to another man page. The
  target of this link has been corrected.

  All users of cups should upgrade to these updated packages, which resolve
  these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-013.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1125", "CVE-2004-1267", "CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270");
script_summary(english: "Check for the version of the cups packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cups-1.1.17-13.3.22", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.17-13.3.22", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.22", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
