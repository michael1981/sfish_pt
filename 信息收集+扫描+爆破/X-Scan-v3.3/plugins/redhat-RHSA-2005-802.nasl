
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20060);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-802: xloadimage");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-802");
 script_set_attribute(attribute: "description", value: '
  A new xloadimage package that fixes bugs in handling malformed tiff and
  pbm/pnm/ppm images, and in handling metacharacters in file names is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The xloadimage utility displays images in an X Window System window, loads
  images into the root window, or writes images into a file. Xloadimage
  supports many image types (including GIF, TIFF, JPEG, XPM, and XBM).

  A flaw was discovered in xloadimage via which an attacker can construct a
  NIFF image with a very long embedded image title. This image can cause a
  buffer overflow. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-3178 to this issue.

  All users of xloadimage should upgrade to this erratum package, which
  contains backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-802.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3178");
script_summary(english: "Check for the version of the xloadimage packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xloadimage-4.1-36.RHEL2.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xloadimage-4.1-36.RHEL3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xloadimage-4.1-36.RHEL4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
