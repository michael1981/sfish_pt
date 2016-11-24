
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12352);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2003-016: fileutils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-016");
 script_set_attribute(attribute: "description", value: '
  Updated fileutils packages are available which fix a race condition in
  recursive remove and move commands.

  The fileutils package includes a number of GNU versions of common and
  popular file management utilities.

  A race condition in recursive use of rm and mv commands in fileutils 4.1
  and earlier could allow local users to delete files and directories as the
  user running fileutils if the user has write access to part of the tree
  being moved or deleted.

  In addition, a bug in the way that the chown command parses --from options
  has also been fixed in these packages, bringing the command into Linux
  Standard Base (LSB) compliance.

  Users of Red Hat Linux Advanced Server should install the upgraded
  fileutils packages which contain patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-016.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0435");
script_summary(english: "Check for the version of the fileutils packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"fileutils-4.1-10.1", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
