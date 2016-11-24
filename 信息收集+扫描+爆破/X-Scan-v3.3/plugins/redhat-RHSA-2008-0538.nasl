
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33192);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0538: openoffice.org");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0538");
 script_set_attribute(attribute: "description", value: '
  Updated openoffice.org packages to correct two security issues are now
  available for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  OpenOffice.org is an office productivity suite that includes desktop
  applications such as a word processor, spreadsheet, presentation manager,
  formula editor, and drawing program.

  Sean Larsson found a heap overflow flaw in the OpenOffice memory allocator.
  If a carefully crafted file was opened by a victim, an attacker could use
  the flaw to crash OpenOffice.org or, possibly, execute arbitrary code.
  (CVE-2008-2152)

  It was discovered that certain libraries in the Red Hat Enterprise Linux 3
  and 4 openoffice.org packages had an insecure relative RPATH (runtime
  library search path) set in the ELF (Executable and Linking Format) header.
  A local user able to convince another user to run OpenOffice in an
  attacker-controlled directory, could run arbitrary code with the privileges
  of the victim. (CVE-2008-2366)

  All users of openoffice.org are advised to upgrade to these updated
  packages, which contain backported fixes which correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0538.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2152", "CVE-2008-2366");
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

if ( rpm_check( reference:"openoffice.org-1.1.2-42.2.0.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-i18n-1.1.2-42.2.0.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-libs-1.1.2-42.2.0.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-1.1.5-10.6.0.5.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-i18n-1.1.5-10.6.0.5.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-kde-1.1.5-10.6.0.5.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-libs-1.1.5-10.6.0.5.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
