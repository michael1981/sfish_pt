
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12369);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2003-065: XFree");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-065");
 script_set_attribute(attribute: "description", value: '
  Updated XFree86 packages that resolve various security issues and
  additionally provide a number of bug fixes and enhancements are now
  available for Red Hat Enterprise Linux 2.1.

  XFree86 is an implementation of the X Window System, which provides the
  graphical user interface, video drivers, etc. for Linux systems.

  A number of security vulnerabilities have been found and fixed. In
  addition, various other bug fixes, driver updates, and other enhancements
  have been made.

  Security fixes:

  Xterm, provided as part of the XFree86 packages, provides an escape
  sequence for reporting the current window title. This escape sequence
  essentially takes the current title and places it directly on the command
  line. An attacker can craft an escape sequence that sets the victim\'s Xterm
  window title to an arbitrary command, and then reports it to the command
  line. Since it is not possible to embed a carriage return into the window
  title, the attacker would then have to convince the victim to press Enter
  for the shell to process the title as a command, although the attacker
  could craft other escape sequences that might convince the victim to do so.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2003-0063 to this issue.

  It is possible to lock up versions of Xterm by sending an invalid DEC
  UDK escape sequence. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2003-0071 to this issue.

  The xdm display manager, with the authComplain variable set to false,
  allows arbitrary attackers to connect to the X server if the xdm auth
  directory does not exist. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2002-1510 to this issue.

  These erratum packages also contain an updated fix for CAN-2002-0164, a
  vulnerability in the MIT-SHM extension of the X server that allows local
  users to read and write arbitrary shared memory. The original fix did not
  cover the case where the X server is started from xdm.

  The X server was setting the /dev/dri directory permissions incorrectly,
  which resulted in the directory being world writable. It now sets the
  directory permissions to a safe value. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2001-1409 to
  this issue.

  Driver updates and other fixes:

  The Rage 128 video driver (r128) has been updated to provide 2D support
  for all previously unsupported ATI Rage 128 hardware. DRI 3D support
  should also work on the majority of Rage 128 hardware.

  Bad page size assumptions in the ATI Radeon video driver (radeon) have
  been fixed, allowing the driver to work properly on ia64 and other
  architectures where the page size is not fixed.

  A long-standing XFree86 bug has been fixed. This bug occurs when any form
  of system clock skew (such as NTP clock synchronization, APM suspend/resume
  cycling on laptops, daylight savings time changeover, or even manually
  setting the system clock forward or backward) could result in odd
  application behavior, mouse and keyboard lockups, or even an X server hang
  or crash.

  The S3 Savage driver (savage) has been updated to the upstream author\'s
  latest version "1.1.27t", which should fix numerous bugs reported by
  various users, as well as adding support for some newer savage hardware.

  Users are advised to upgrade to these updated packages, which contain
  XFree86 version 4.1.0 with patches correcting these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-065.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2001-1409", "CVE-2002-0164", "CVE-2002-1510", "CVE-2003-0063", "CVE-2003-0071");
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

if ( rpm_check( reference:"XFree86-100dpi-fonts-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-75dpi-fonts-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-100dpi-fonts-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-75dpi-fonts-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-100dpi-fonts-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-75dpi-fonts-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-100dpi-fonts-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-75dpi-fonts-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xnest-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xvfb-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-cyrillic-fonts-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-devel-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-doc-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-tools-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-twm-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-xdm-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-xf86cfg-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"XFree86-xfs-4.1.0-49.RHEL", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
