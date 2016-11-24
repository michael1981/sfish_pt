
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17187);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-103: perl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-103");
 script_set_attribute(attribute: "description", value: '
  Updated Perl packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team

  Perl is a high-level programming language commonly used for system
  administration utilities and Web programming.

  Kevin Finisterre discovered a stack based buffer overflow flaw in sperl,
  the Perl setuid wrapper. A local user could create a sperl executable
  script with a carefully created path name, overflowing the buffer and
  leading to root privilege escalation. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-0156 to
  this issue.

  Kevin Finisterre discovered a flaw in sperl which can cause debugging
  information to be logged to arbitrary files. By setting an environment
  variable, a local user could cause sperl to create, as root, files with
  arbitrary filenames, or append the debugging information to existing files.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2005-0155 to this issue.

  An unsafe file permission bug was discovered in the rmtree() function in
  the File::Path module. The rmtree() function removes files and directories
  in an insecure manner, which could allow a local user to read or delete
  arbitrary files. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0452 to this issue.

  Users of Perl are advised to upgrade to this updated package, which
  contains backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-103.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0452", "CVE-2005-0155", "CVE-2005-0156");
script_summary(english: "Check for the version of the perl packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"perl-5.8.5-12.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-suidperl-5.8.5-12.1.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
