
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25139);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0235: util");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0235");
 script_set_attribute(attribute: "description", value: '
  An updated util-linux package that corrects a security issue and fixes
  several bugs is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The util-linux package contains a collection of basic system utilities.

  A flaw was found in the way the login process handled logins which did not
  require authentication. Certain processes which conduct their own
  authentication could allow a remote user to bypass intended access policies
  which would normally be enforced by the login process. (CVE-2006-7108)

  This update also fixes the following bugs:

  * The partx, addpart and delpart commands were not documented.

  * The "umount -l" command did not work on hung NFS mounts with cached data.

  * The mount command did not mount NFS V3 share where sec=none was
  specified.

  * The mount command did not read filesystem LABEL from unpartitioned disks.

  * The mount command did not recognize labels on VFAT filesystems.

  * The fdisk command did not support 4096 sector size for the "-b" option.

  * The mount man page did not list option "mand" or information about
  /etc/mtab limitations.

  All users of util-linux should upgrade to these updated packages, which
  contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0235.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-7108");
script_summary(english: "Check for the version of the util packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"util-linux-2.12a-16.EL4.25", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
