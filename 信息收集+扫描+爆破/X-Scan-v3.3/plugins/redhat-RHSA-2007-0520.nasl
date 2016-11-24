
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25723);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0520: xorg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0520");
 script_set_attribute(attribute: "description", value: '
  Updated X.org packages that address a flaw in the way the X.Org X11 xfs
  font server starts are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The X.Org X11 xfs font server provides a standard mechanism for an X server
  to communicate with a font renderer.

  A temporary file flaw was found in the way the X.Org X11 xfs font server
  startup script executes. A local user could modify the permissions of a
  file of their choosing, possibly elevating their local privileges.
  (CVE-2007-3103)

  Users of the X.org X11 xfs font server should upgrade to these updated
  packages, which contain a backported patch and are not vulnerable to this
  issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0520.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3103");
script_summary(english: "Check for the version of the xorg packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xorg-x11-xfs-1.0.2-4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xfs-utils-1.0.2-4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
