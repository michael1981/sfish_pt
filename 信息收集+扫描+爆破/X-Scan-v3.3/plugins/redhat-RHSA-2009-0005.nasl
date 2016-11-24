
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35301);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0005: gnome");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0005");
 script_set_attribute(attribute: "description", value: '
  Updated GNOME VFS packages that fix a security issue are now available for
  Red Hat Enterprise Linux 2.1, 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  GNOME VFS is the GNOME virtual file system. It provides a modular
  architecture and ships with several modules that implement support for
  various local and remote file systems as well as numerous protocols,
  including HTTP, FTP, and others.

  A buffer overflow flaw was discovered in the GNOME virtual file system when
  handling data returned by CDDB servers. If a user connected to a malicious
  CDDB server, an attacker could use this flaw to execute arbitrary code on
  the victim\'s machine. (CVE-2005-0706)

  Users of gnome-vfs and gnome-vfs2 are advised to upgrade to these updated
  packages, which contain a backported patch to correct this issue. All
  running GNOME sessions must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0005.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0706");
script_summary(english: "Check for the version of the gnome packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gnome-vfs-1.0.1-18.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnome-vfs-devel-1.0.1-18.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnome-vfs2-2.2.5-2E.3.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnome-vfs2-devel-2.2.5-2E.3.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnome-vfs2-2.8.2-8.7.el4_7.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnome-vfs2-devel-2.8.2-8.7.el4_7.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnome-vfs2-smb-2.8.2-8.7.el4_7.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
