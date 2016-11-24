
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20204);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2005-806: cpio");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-806");
 script_set_attribute(attribute: "description", value: '
  An updated cpio package that fixes multiple issues is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  GNU cpio copies files into or out of a cpio or tar archive.

  A race condition bug was found in cpio. It is possible for a local
  malicious user to modify the permissions of a local file if they have write
  access to a directory in which a cpio archive is being extracted. The
  Common Vulnerabilities and Exposures project has assigned the name
  CVE-2005-1111 to this issue.

  It was discovered that cpio uses a 0 umask when creating files using the -O
  (archive) option. This creates output files with mode 0666 (all users can
  read and write) regardless of the user\'s umask setting. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-1999-1572 to this issue.

  All users of cpio are advised to upgrade to this updated package, which
  contains backported fixes for these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-806.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-1999-1572", "CVE-2005-1111");
script_summary(english: "Check for the version of the cpio packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cpio-2.4.2-25", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
