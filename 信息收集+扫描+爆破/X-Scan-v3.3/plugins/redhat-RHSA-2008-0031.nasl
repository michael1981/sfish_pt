
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(30003);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0031: xorg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0031");
 script_set_attribute(attribute: "description", value: '
  Updated xorg-x11-server packages that fix several security issues are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  [Updated 18th January 2008]
  The original packages distributed with this errata had a bug which could
  cause some X applications to fail on 32-bit platforms. We have updated the
  packages to correct this bug.

  X.Org is an open source implementation of the X Window System. It provides
  basic low-level functionality that full-fledged graphical user interfaces
  are designed upon.

  Two integer overflow flaws were found in the X.Org server\'s EVI and MIT-SHM
  modules. A malicious authorized client could exploit these issues to cause
  a denial of service (crash), or potentially execute arbitrary code with
  root privileges on the X.Org server. (CVE-2007-6429)

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

  A flaw was found in the X.Org server\'s XC-SECURITY extension, that could
  have allowed a local user to verify the existence of an arbitrary file,
  even in directories that are not normally accessible to that user.
  (CVE-2007-5958)

  Users of xorg-x11-server should upgrade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0031.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429");
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

if ( rpm_check( reference:"xorg-x11-server-Xdmx-1.1.1-48.26.el5_1.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-Xephyr-1.1.1-48.26.el5_1.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-Xnest-1.1.1-48.26.el5_1.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-Xorg-1.1.1-48.26.el5_1.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-Xvfb-1.1.1-48.26.el5_1.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-sdk-1.1.1-48.26.el5_1.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
