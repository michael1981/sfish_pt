
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12446);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-004: cvs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-004");
 script_set_attribute(attribute: "description", value: '
  Updated cvs packages closing a vulnerability that could allow cvs to
  attempt to create files and directories in the root file system are now
  available.

  CVS is a version control system frequently used to manage source code
  repositories.

  A flaw was found in versions of CVS prior to 1.11.10 where a malformed
  module request could cause the CVS server to attempt to create files or
  directories at the root level of the file system. However, normal file
  system permissions would prevent the creation of these misplaced
  directories. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2003-0977 to this issue.

  Users of CVS are advised to upgrade to these erratum packages, which
  contain a patch correcting this issue.

  For Red Hat Enterprise Linux 2.1, these updates also fix an off-by-one
  overflow in the CVS PreservePermissions code. The PreservePermissions
  feature is not used by default (and can only be used for local CVS). The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2002-0844 to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-004.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0844", "CVE-2003-0977");
script_summary(english: "Check for the version of the cvs packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cvs-1.11.1p1-9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.2-14", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
