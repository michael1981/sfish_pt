
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34505);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0965: lynx");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0965");
 script_set_attribute(attribute: "description", value: '
  An updated lynx package that corrects two security issues is now available
  for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Lynx is a text-based Web browser.

  An arbitrary command execution flaw was found in the Lynx "lynxcgi:" URI
  handler. An attacker could create a web page redirecting to a malicious URL
  that could execute arbitrary code as the user running Lynx in the
  non-default "Advanced" user mode. (CVE-2008-4690)

  Note: In these updated lynx packages, Lynx will always prompt users before
  loading a "lynxcgi:" URI. Additionally, the default lynx.cfg configuration
  file now marks all "lynxcgi:" URIs as untrusted by default.

  A flaw was found in a way Lynx handled ".mailcap" and ".mime.types"
  configuration files. Files in the browser\'s current working directory were
  opened before those in the user\'s home directory. A local attacker, able to
  convince a user to run Lynx in a directory under their control, could
  possibly execute arbitrary commands as the user running Lynx.
  (CVE-2006-7234)

  All users of Lynx are advised to upgrade to this updated package, which
  contains backported patches correcting these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0965.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-7234", "CVE-2008-4690");
script_summary(english: "Check for the version of the lynx packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lynx-2.8.5-28.1.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.4-18.1.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-11.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-18.2.el4_7.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
