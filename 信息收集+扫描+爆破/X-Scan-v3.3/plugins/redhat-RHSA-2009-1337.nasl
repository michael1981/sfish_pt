
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40839);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1337: gfs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1337");
 script_set_attribute(attribute: "description", value: '
  An updated gfs2-utils package that fixes multiple security issues and
  various bugs is now available for Red Hat Enterprise Linux 5.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The gfs2-utils package provides the user-space tools necessary to mount,
  create, maintain, and test GFS2 file systems.

  Multiple insecure temporary file use flaws were discovered in GFS2 user
  level utilities. A local attacker could use these flaws to overwrite an
  arbitrary file writable by a victim running those utilities (typically
  root) with the output of the utilities via a symbolic link attack.
  (CVE-2008-6552)

  This update also fixes the following bugs:

  * gfs2_fsck now properly detects and repairs problems with sequence numbers
  on GFS2 file systems.

  * GFS2 user utilities now use the file system UUID.

  * gfs2_grow now properly updates the file system size during operation.

  * gfs2_fsck now returns the proper exit codes.

  * gfs2_convert now properly frees blocks when removing free blocks up to
  height 2.

  * the gfs2_fsck manual page has been renamed to fsck.gfs2 to match current
  standards.

  * the \'gfs2_tool df\' command now provides human-readable output.

  * mounting GFS2 file systems with the noatime or noquota option now works
  properly.

  * new capabilities have been added to the gfs2_edit tool to help in testing
  and debugging GFS and GFS2 issues.

  * the \'gfs2_tool df\' command no longer segfaults on file systems with a
  block size other than 4k.

  * the gfs2_grow manual page no longer references the \'-r\' option, which has
  been removed.

  * the \'gfs2_tool unfreeze\' command no longer hangs during use.

  * gfs2_convert no longer corrupts file systems when converting from GFS to
  GFS2.

  * gfs2_fsck no longer segfaults when encountering a block which is listed
  as both a data and stuffed directory inode.

  * gfs2_fsck can now fix file systems even if the journal is already locked
  for use.

  * a GFS2 file system\'s metadata is now properly copied with \'gfs2_edit
  savemeta\' and \'gfs2_edit restoremeta\'.

  * the gfs2_edit savemeta function now properly saves blocks of type 2.

  * \'gfs2_convert -vy\' now works properly on the PowerPC architecture.

  * when mounting a GFS2 file system as \'/\', mount_gfs2 no longer fails after
  being unable to find the file system in \'/proc/mounts\'.

  * gfs2_fsck no longer segfaults when fixing \'EA leaf block type\' problems.

  All gfs2-utils users should upgrade to this updated package, which resolves
  these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1337.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-6552");
script_summary(english: "Check for the version of the gfs packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gfs2-utils-0.1.62-1.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
