
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24896);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0033: openoffice.org");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0033");
 script_set_attribute(attribute: "description", value: '
  Updated openoffice.org packages to correct security issues are now
  available for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  OpenOffice.org is an office productivity suite that includes desktop
  applications such as a word processor, spreadsheet, presentation manager,
  formula editor, and drawing program.

  iDefense reported an integer overflow flaw in libwpd, a library used
  internally to OpenOffice.org for handling Word Perfect documents. An
  attacker could create a carefully crafted Word Perfect file that could
  cause OpenOffice.org to crash or possibly execute arbitrary code if the
  file was opened by a victim. (CVE-2007-1466)

  John Heasman discovered a stack overflow in the StarCalc parser in
  OpenOffice.org. An attacker could create a carefully crafted StarCalc file
  that could cause OpenOffice.org to crash or possibly execute arbitrary code
  if the file was opened by a victim. (CVE-2007-0238)

  Flaws were discovered in the way OpenOffice.org handled hyperlinks. An
  attacker could create an OpenOffice.org document which could run commands
  if a victim opened the file and clicked on a malicious hyperlink.
  (CVE-2007-0239)

  All users of OpenOffice.org are advised to upgrade to these updated
  packages, which contain backported fixes for these issues.

  Red Hat would like to thank Fridrich   trba for alerting us to the issue
  CVE-2007-1466 and providing a patch, and John Heasman for
  CVE-2007-0238.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0033.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-0238", "CVE-2007-0239", "CVE-2007-1466");
script_summary(english: "Check for the version of the openoffice.org packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openoffice.org-1.1.2-38.2.0.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-i18n-1.1.2-38.2.0.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-libs-1.1.2-38.2.0.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-1.1.5-10.6.0.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-i18n-1.1.5-10.6.0.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-kde-1.1.5-10.6.0.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-libs-1.1.5-10.6.0.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
