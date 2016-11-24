
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17146);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-080: cpio");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-080");
 script_set_attribute(attribute: "description", value: '
  An updated cpio package that fixes a umask bug and supports large files
  (>2GB) is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team

  GNU cpio copies files into or out of a cpio or tar archive.

  It was discovered that cpio uses a 0 umask when creating files using the -O
  (archive) option. This creates output files with mode 0666 (all can read
  and write) regardless of the user\'s umask setting. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-1999-1572 to this issue.

  All users of cpio should upgrade to this updated package, which resolves
  this issue, and adds support for large files (> 2GB).


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-080.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-1999-1572");
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

if ( rpm_check( reference:"cpio-2.5-3e.3", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
