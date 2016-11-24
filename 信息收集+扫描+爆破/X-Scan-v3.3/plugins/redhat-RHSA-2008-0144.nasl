
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40715);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2008-0144: acroread");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0144");
 script_set_attribute(attribute: "description", value: '
  Updated acroread packages that fix several security issues are now
  available for Red Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The Adobe Reader allows users to view and print documents in portable
  document format (PDF).

  Several flaws were found in the way Adobe Reader processed malformed PDF
  files. An attacker could create a malicious PDF file which could execute
  arbitrary code if opened by a victim. (CVE-2007-5659, CVE-2007-5663,
  CVE-2007-5666, CVE-2008-0726)

  A flaw was found in the way the Adobe Reader browser plug-in honored
  certain requests. A malicious PDF file could cause the browser to request
  an unauthorized URL, allowing for a cross-site request forgery attack.
  (CVE-2007-0044)

  A flaw was found in Adobe Reader\'s JavaScript API DOC.print function. A
  malicious PDF file could silently trigger non-interactive printing of the
  document, causing multiple copies to be printed without the users consent.
  (CVE-2008-0667)

  Additionally, this update fixes multiple unknown flaws in Adobe Reader.
  When the information regarding these flaws is made public by Adobe, it will
  be added to this advisory. (CVE-2008-0655)

  Note: Adobe have yet to release security fixed versions of Adobe 7. All
  users of Adobe Reader are, therefore, advised to install these updated
  packages. They contain Adobe Reader version 8.1.2, which is not vulnerable
  to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0144.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-0044", "CVE-2007-5659", "CVE-2007-5663", "CVE-2007-5666", "CVE-2008-0655", "CVE-2008-0667", "CVE-2008-0726");
script_summary(english: "Check for the version of the acroread packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"acroread-8.1.2-1.el3.6", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acroread-plugin-8.1.2-1.el3.6", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acroread-8.1.2-1.el4.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acroread-plugin-8.1.2-1.el4.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acroread-8.1.2-1.el4.2", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acroread-plugin-8.1.2-1.el4.2", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
