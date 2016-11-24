
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15427);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-412: arts");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-412");
 script_set_attribute(attribute: "description", value: '
  Updated kdelib and kdebase packages that resolve multiple security issues
  are now available.

  The kdelibs packages include libraries for the K Desktop Environment.
  The kdebase packages include core applications for the K Desktop
  Environment.

  Andrew Tuitt reported that versions of KDE up to and including 3.2.3 create
  temporary directories with predictable names. A local attacker could
  prevent KDE applications from functioning correctly, or overwrite files
  owned by other users by creating malicious symlinks. The Common
  Vulnerabilities and Exposures project has assigned the name CAN-2004-0689
  to this issue.

  WESTPOINT internet reconnaissance services has discovered that the KDE web
  browser Konqueror allows websites to set cookies for certain country
  specific secondary top level domains. An attacker within one of the
  affected domains could construct a cookie which would be sent to all other
  websites within the domain leading to a session fixation attack. This
  issue does not affect popular domains such as .co.uk, .co.in, or .com. The
  Common Vulnerabilities and Exposures project has assigned the name
  CAN-2004-0721 to this issue.

  A frame injection spoofing vulnerability has been discovered in the
  Konqueror web browser. This issue could allow a malicious website to show
  arbitrary content in a named frame of a different browser window. The
  Common Vulnerabilities and Exposures project has assigned the name
  CAN-2004-0746 to this issue.

  All users of KDE are advised to upgrade to these erratum packages,
  which contain backported patches from the KDE team for these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-412.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0689", "CVE-2004-0721", "CVE-2004-0746");
script_summary(english: "Check for the version of the arts packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"arts-2.2.2-13", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-2.2.2-12", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-2.2.2-12", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-2.2.2-13", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-2.2.2-13", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-2.2.2-13", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-devel-2.2.2-13", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-3.1.3-5.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.1.3-5.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-3.1.3-6.6", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.1.3-6.6", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
