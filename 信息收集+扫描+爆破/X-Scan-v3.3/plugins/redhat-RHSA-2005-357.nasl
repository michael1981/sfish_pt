
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18469);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-357: gzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-357");
 script_set_attribute(attribute: "description", value: '
  An updated gzip package is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The gzip package contains the GNU gzip data compression program.

  A bug was found in the way zgrep processes file names. If a user can be
  tricked into running zgrep on a file with a carefully crafted file name,
  arbitrary commands could be executed as the user running zgrep. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-0758 to this issue.

  A bug was found in the way gunzip modifies permissions of files being
  decompressed. A local attacker with write permissions in the directory in
  which a victim is decompressing a file could remove the file being written
  and replace it with a hard link to a different file owned by the victim.
  gunzip then gives the linked file the permissions of the uncompressed file.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2005-0988 to this issue.

  A directory traversal bug was found in the way gunzip processes the -N
  flag. If a victim decompresses a file with the -N flag, gunzip fails to
  sanitize the path which could result in a file owned by the victim being
  overwritten. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-1228 to this issue.

  Users of gzip should upgrade to this updated package, which contains
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-357.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0758", "CVE-2005-0988", "CVE-2005-1228");
script_summary(english: "Check for the version of the gzip packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gzip-1.3-18.rhel2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gzip-1.3.3-12.rhel3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gzip-1.3.3-15.rhel4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
