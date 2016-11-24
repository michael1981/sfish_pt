
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39531);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1130: kdegraphics");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1130");
 script_set_attribute(attribute: "description", value: '
  Updated kdegraphics packages that fix two security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The kdegraphics packages contain applications for the K Desktop Environment
  (KDE). Scalable Vector Graphics (SVG) is an XML-based language to describe
  vector images. KSVG is a framework aimed at implementing the latest W3C SVG
  specifications.

  A use-after-free flaw was found in the KDE KSVG animation element
  implementation. A remote attacker could create a specially-crafted SVG
  image, which once opened by an unsuspecting user, could cause a denial of
  service (Konqueror crash) or, potentially, execute arbitrary code with the
  privileges of the user running Konqueror. (CVE-2009-1709)

  A NULL pointer dereference flaw was found in the KDE, KSVG SVGList
  interface implementation. A remote attacker could create a
  specially-crafted SVG image, which once opened by an unsuspecting user,
  would cause memory corruption, leading to a denial of service (Konqueror
  crash). (CVE-2009-0945)

  All users of kdegraphics should upgrade to these updated packages, which
  contain backported patches to correct these issues. The desktop must be
  restarted (log out, then log back in) for this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1130.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0945", "CVE-2009-1709");
script_summary(english: "Check for the version of the kdegraphics packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdegraphics-3.5.4-13.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
