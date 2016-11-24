
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14625);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-323: lha");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-323");
 script_set_attribute(attribute: "description", value: '
  An updated lha package that fixes a buffer overflow is now available.

  LHA is an archiving and compression utility for LHarc format archives.

  Lukasz Wojtow discovered a stack-based buffer overflow in all versions
  of lha up to and including version 1.14. A carefully created archive could
  allow an attacker to execute arbitrary code when a victim extracts or tests
  the archive. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0769 to this issue.

  Buffer overflows were discovered in the command line processing of all
  versions of lha up to and including version 1.14. If a malicious user
  could trick a victim into passing a specially crafted command line to the
  lha command, it is possible that arbitrary code could be executed. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the names CAN-2004-0771 and CAN-2004-0694 to these issues.

  Thomas Biege discovered a shell meta character command execution
  vulnerability in all versions of lha up to and including 1.14. An attacker
  could create a directory with shell meta characters in its name which could
  lead to arbitrary command execution. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-0745 to
  this issue.

  Users of lha should update to this updated package which contains
  backported patches and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-323.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0694", "CVE-2004-0745", "CVE-2004-0769", "CVE-2004-0771");
script_summary(english: "Check for the version of the lha packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lha-1.14i-10.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
