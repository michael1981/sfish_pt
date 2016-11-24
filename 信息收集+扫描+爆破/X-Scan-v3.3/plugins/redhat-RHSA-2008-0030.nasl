
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(30002);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0030: xorg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0030");
 script_set_attribute(attribute: "description", value: '
  Updated xorg-x11 packages that fix several security issues are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  [Updated 18th January 2008]
  The original packages distributed with this errata had a bug which could
  cause some X applications to fail on 32-bit platforms. We have updated the
  packages to correct this bug.

  The xorg-x11 packages contain X.Org, an open source implementation of the X
  Window System. It provides the basic low-level functionality that
  full-fledged graphical user interfaces are designed upon.

  Two integer overflow flaws were found in the X.Org server\'s EVI and MIT-SHM
  modules. A malicious authorized client could exploit these issues to cause
  a denial of service (crash), or potentially execute arbitrary code with
  root privileges on the X.Org server. (CVE-2007-6429)

  A heap based buffer overflow flaw was found in the way the X.Org server
  handled malformed font files. A malicious local user could exploit these
  issues to potentially execute arbitrary code with the privileges of the
  X.Org server. (CVE-2008-0006)

  A memory corruption flaw was found in the X.Org server\'s XInput extension.
  A malicious authorized client could exploit this issue to cause a denial of
  service (crash), or potentially execute arbitrary code with root privileges
  on the X.Org server. (CVE-2007-6427)

  An input validation flaw was found in the X.Org server\'s XFree86-Misc
  extension. A malicious authorized client could exploit this issue to cause
  a denial of service (crash), or potentially execute arbitrary code with
  root privileges on the X.Org server. (CVE-2007-5760)

  An information disclosure flaw was found in the X.Org server\'s TOG-CUP
  extension. A malicious authorized client could exploit this issue to cause
  a denial of service (crash), or potentially view arbitrary memory content
  within the X server\'s address space. (CVE-2007-6428)

  An integer and heap overflow flaw were found in the X.Org font server, xfs.
  A user with the ability to connect to the font server could have been able
  to cause a denial of service (crash), or potentially execute arbitrary code
  with the permissions of the font server. (CVE-2007-4568, CVE-2007-4990)

  A flaw was found in the X.Org server\'s XC-SECURITY extension, that could
  have allowed a local user to verify the existence of an arbitrary file,
  even in directories that are not normally accessible to that user.
  (CVE-2007-5958)

  Users of xorg-x11 should upgrade to these updated packages, which contain
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0030.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4568", "CVE-2007-4990", "CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2008-0006");
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

if ( rpm_check( reference:"xorg-x11-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xdmx-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xnest-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xvfb-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-devel-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-doc-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-font-utils-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-libs-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-sdk-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-tools-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-twm-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xauth-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xdm-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xfs-6.8.2-1.EL.33.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
