
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14734);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-466: gtk");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-466");
 script_set_attribute(attribute: "description", value: '
  Updated gtk2 packages that fix several security flaws and bugs are now
  available.

  The gtk2 package contains the GIMP ToolKit (GTK+), a library for creating
  graphical user interfaces for the X Window System.

  During testing of a previously fixed flaw in Qt (CAN-2004-0691), a flaw was
  discovered in the BMP image processor of gtk2. An attacker could create a
  carefully crafted BMP file which would cause an application to enter an
  infinite loop and not respond to user input when the file was opened by a
  victim. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CAN-2004-0753 to this issue.

  During a security audit Chris Evans discovered a stack and a heap overflow
  in the XPM image decoder. An attacker could create a carefully crafted XPM
  file which could cause an application linked with gtk2 to crash or possibly
  execute arbitrary code when the file was opened by a victim.
  (CAN-2004-0782, CAN-2004-0783)

  Chris Evans also discovered an integer overflow in the ICO image decoder.
  An attacker could create a carefully crafted ICO file which could cause an
  application linked with gtk2 to crash when the file was opened by a victim.
  (CAN-2004-0788)

  This updated gtk2 package also fixes a few key combination bugs on various
  X servers, such as Hummingbird, ReflectionX, and X-Win32. If a server was
  configured to use the Swiss German, Swiss French, or France French keyboard
  layouts, Mode_Switched characters were unable to be entered within GTK
  based applications.

  Users of gtk2 are advised to upgrade to these packages which contain
  backported patches and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-466.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0753", "CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788");
script_summary(english: "Check for the version of the gtk packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gtk2-2.2.4-8.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gtk2-devel-2.2.4-8.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
