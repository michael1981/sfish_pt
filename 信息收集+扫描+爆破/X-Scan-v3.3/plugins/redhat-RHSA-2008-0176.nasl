
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32019);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0176: openoffice.org");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0176");
 script_set_attribute(attribute: "description", value: '
  Updated openoffice.org 1.x packages to correct multiple security issues are
  now available for Red Hat Enterprise Linux 3 and Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  OpenOffice.org is an office productivity suite that includes desktop
  applications such as a word processor, spreadsheet, presentation manager,
  formula editor, and drawing program.

  A heap overflow flaw was found in the EMF parser. An attacker could create
  a carefully crafted EMF file that could cause OpenOffice.org to crash or
  possibly execute arbitrary code if the malicious EMF image was added to a
  document or if a document containing the malicious EMF file was opened by a
  victim. (CVE-2007-5746)

  A heap overflow flaw was found in the OLE Structured Storage file parser.
  (OLE Structured Storage is a format used by Microsoft Office documents.) An
  attacker could create a carefully crafted OLE file that could cause
  OpenOffice.org to crash or possibly execute arbitrary code if the file was
  opened by a victim. (CVE-2008-0320)

  All users of OpenOffice.org are advised to upgrade to these updated
  packages, which contain backported fixes to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0176.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5746", "CVE-2008-0320");
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

if ( rpm_check( reference:"openoffice.org-1.1.2-41.2.0.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-i18n-1.1.2-41.2.0.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-libs-1.1.2-41.2.0.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-1.1.5-10.6.0.3.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-i18n-1.1.5-10.6.0.3.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-kde-1.1.5-10.6.0.3.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-libs-1.1.5-10.6.0.3.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
