
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14211);
 script_version ("$Revision: 1.12 $");
 script_name(english: "RHSA-2004-373: gnome");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-373");
 script_set_attribute(attribute: "description", value: '
  Updated GNOME VFS packages that remove potential extfs-related
  vulnerabilities are now available.

  GNOME VFS is the GNOME virtual file system. It provides a modular
  architecture and ships with several modules that implement support for file
  systems, HTTP, FTP, and others. The extfs backends make it possible to
  implement file systems for GNOME VFS using scripts.

  Flaws have been found in several of the GNOME VFS extfs backend scripts.
  Red Hat Enterprise Linux ships with vulnerable scripts, but they are not
  used by default. An attacker who is able to influence a user to open a
  specially-crafted URI using gnome-vfs could perform actions as that user.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2004-0494 to this issue.

  Users of Red Hat Enterprise Linux should upgrade to these updated packages,
  which remove these unused scripts.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-373.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0494");
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

if ( rpm_check( reference:"gnome-vfs-1.0.1-18.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnome-vfs-devel-1.0.1-18.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnome-vfs2-2.2.5-2E.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnome-vfs2-devel-2.2.5-2E.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
