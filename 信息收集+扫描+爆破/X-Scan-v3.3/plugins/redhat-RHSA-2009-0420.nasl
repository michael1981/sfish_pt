
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36159);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0420: ghostscript");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0420");
 script_set_attribute(attribute: "description", value: '
  Updated ghostscript packages that fix multiple security issues are now
  available for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ghostscript is a set of software that provides a PostScript interpreter, a
  set of C procedures (the Ghostscript library, which implements the graphics
  capabilities in the PostScript language) and an interpreter for Portable
  Document Format (PDF) files.

  It was discovered that the Red Hat Security Advisory RHSA-2009:0345 did not
  address all possible integer overflow flaws in Ghostscript\'s International
  Color Consortium Format library (icclib). Using specially-crafted ICC
  profiles, an attacker could create a malicious PostScript or PDF file with
  embedded images that could cause Ghostscript to crash or, potentially,
  execute arbitrary code when opened. (CVE-2009-0792)

  A missing boundary check was found in Ghostscript\'s CCITTFax decoding
  filter. An attacker could create a specially-crafted PostScript or PDF file
  that could cause Ghostscript to crash or, potentially, execute arbitrary
  code when opened. (CVE-2007-6725)

  Users of ghostscript are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0420.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-6725", "CVE-2009-0792");
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

if ( rpm_check( reference:"ghostscript-7.05-32.1.20", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-devel-7.05-32.1.20", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hpijs-1.3-32.1.20", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-7.07-33.2.el4_7.8", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-devel-7.07-33.2.el4_7.8", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-gtk-7.07-33.2.el4_7.8", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
