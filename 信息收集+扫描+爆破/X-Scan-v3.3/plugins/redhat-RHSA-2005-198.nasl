
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18443);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-198: fonts");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-198");
 script_set_attribute(attribute: "description", value: '
  Updated xorg-x11 packages that fix a security issue as well as various bugs
  are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  X.Org X11 is the X Window System which provides the core functionality
  of the Linux GUI desktop.

  An integer overflow flaw was found in libXpm, which is used by some
  applications for loading of XPM images. An attacker could create a
  carefully crafted XPM file in such a way that it could cause an application
  linked with libXpm to execute arbitrary code when the file was opened by a
  victim. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CAN-2005-0605 to this issue.

  Since the initial release of Red Hat Enterprise Linux 4, a number of issues
  have been addressed in the X.Org X11 X Window System. This erratum also
  updates X11R6.8 to the latest stable point release (6.8.2), which includes
  various stability and reliability fixes including (but not limited to) the
  following:

  - The \'radeon\' driver has been modified to disable "RENDER" acceleration
  by default, due to a bug in the implementation which has not yet
  been isolated. This can be manually re-enabled by using the
  following option in the device section of the X server config file:

  Option "RenderAccel"

  - The \'vmware\' video driver is now available on 64-bit AMD64 and
  compatible systems.

  - The Intel \'i810\' video driver is now available on 64-bit EM64T
  systems.

  - Stability fixes in the X Server\'s PCI handling layer for 64-bit systems,
  which resolve some issues reported by "vesa" and "nv" driver users.

  - Support for Hewlett Packard\'s Itanium ZX2 chipset.

  - Nvidia "nv" video driver update provides support for some of
  the newer Nvidia chipsets, as well as many stability and reliability
  fixes.

  - Intel i810 video driver stability update, which fixes the widely
  reported i810/i815 screen refresh issues many have experienced.

  - Packaging fixes for multilib systems, which permit both 32-bit
  and 64-bit X11 development environments to be simultaneously installed
  without file conflicts.

  In addition to the above highlights, the X.Org X11 6.8.2 release has a
  large number of additional stability fixes which resolve various other
  issues reported since the initial release of Red Hat Enterprise Linux 4.

  All users of X11 should upgrade to these updated packages, which resolve
  these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-198.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0605");
script_summary(english: "Check for the version of the fonts packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"fonts-xorg-100dpi-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fonts-xorg-75dpi-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fonts-xorg-ISO8859-14-100dpi-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fonts-xorg-ISO8859-14-75dpi-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fonts-xorg-ISO8859-15-100dpi-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fonts-xorg-ISO8859-15-75dpi-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fonts-xorg-ISO8859-2-100dpi-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fonts-xorg-ISO8859-2-75dpi-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fonts-xorg-ISO8859-9-100dpi-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fonts-xorg-ISO8859-9-75dpi-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fonts-xorg-base-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fonts-xorg-cyrillic-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fonts-xorg-syriac-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fonts-xorg-truetype-6.8.1.1-1.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xdmx-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xnest-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xvfb-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-devel-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-doc-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-font-utils-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-libs-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-sdk-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-tools-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-twm-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xauth-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xdm-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xfs-6.8.2-1.EL.13.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
