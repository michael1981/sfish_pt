
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25332);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0346: vim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0346");
 script_set_attribute(attribute: "description", value: '
  Updated vim packages that fix a security issue are now available for Red
  Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red Hat
  Security Response Team.

  VIM (VIsual editor iMproved) is a version of the vi editor.

  An arbitrary command execution flaw was found in the way VIM processes
  modelines. If a user with modelines enabled opened a text file containing
  a carefully crafted modeline, arbitrary commands could be executed as the
  user
  running VIM. (CVE-2007-2438)

  Users of VIM are advised to upgrade to these updated packages, which
  resolve this issue.

  Please note: this issue did not affect VIM as distributed with Red Hat
  Enterprise Linux 2.1, 3, or 4.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0346.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2438");
script_summary(english: "Check for the version of the vim packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"vim-X11-7.0.109-3.el5.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-common-7.0.109-3.el5.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-7.0.109-3.el5.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-7.0.109-3.el5.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
