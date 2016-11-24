
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19827);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-081: ghostscript");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-081");
 script_set_attribute(attribute: "description", value: '
  Updated ghostscript packages that fix a PDF output issue and a temporary
  file security bug are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Ghostscript is a program for displaying PostScript files or printing them
  to non-PostScript printers.

  A bug was found in the way several of Ghostscript\'s utility scripts created
  temporary files. A local user could cause these utilities to overwrite
  files that the victim running the utility has write access to. The Common
  Vulnerabilities and Exposures project assigned the name CAN-2004-0967 to
  this issue.

  Additionally, this update addresses the following issue:

  A problem has been identified in the PDF output driver, which can cause
  output to be delayed indefinitely on some systems. The fix has been
  backported from GhostScript 7.07.

  All users of ghostscript should upgrade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-081.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0967");
script_summary(english: "Check for the version of the ghostscript packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ghostscript-7.05-32.1.10", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-devel-7.05-32.1.10", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hpijs-1.3-32.1.10", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
