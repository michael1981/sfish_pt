
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33154);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0512: XFree");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0512");
 script_set_attribute(attribute: "description", value: '
  Updated XFree86 packages that fix several security issues are now available
  for Red Hat Enterprise Linux 2.1.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  XFree86 is an implementation of the X Window System, which provides the
  core functionality for the Linux graphical desktop.

  An input validation flaw was discovered in X.org\'s Security and Record
  extensions. A malicious authorized client could exploit this issue to cause
  a denial of service (crash) or, potentially, execute arbitrary code with
  root privileges on the X.Org server. (CVE-2008-1377)

  An integer overflow flaw was found in X.org\'s Render extension. A malicious
  authorized client could exploit this issue to cause a denial of service
  (crash) or, potentially, execute arbitrary code with root privileges on the
  X.Org server. (CVE-2008-2360)

  An input validation flaw was discovered in X.org\'s MIT-SHM extension. A
  client connected to the X.org server could read arbitrary server memory.
  This could result in the sensitive data of other users of the X.org server
  being disclosed. (CVE-2008-1379)

  Users of XFree86 are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0512.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360");
script_summary(english: "Check for the version of the XFree packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"XFree86-100dpi-fonts-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-75dpi-fonts-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-100dpi-fonts-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-75dpi-fonts-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-100dpi-fonts-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-75dpi-fonts-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-100dpi-fonts-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-75dpi-fonts-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xnest-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xvfb-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-cyrillic-fonts-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-devel-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-doc-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-tools-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-twm-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-xdm-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-xf86cfg-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-xfs-4.1.0-88.EL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
