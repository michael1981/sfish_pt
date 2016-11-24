
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42163);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1504: poppler");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1504");
 script_set_attribute(attribute: "description", value: '
  Updated poppler packages that fix multiple security issues and a bug are
  now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Poppler is a Portable Document Format (PDF) rendering library, used by
  applications such as Evince.

  Multiple integer overflow flaws were found in poppler. An attacker could
  create a malicious PDF file that would cause applications that use poppler
  (such as Evince) to crash or, potentially, execute arbitrary code when
  opened. (CVE-2009-3603, CVE-2009-3608, CVE-2009-3609)

  Red Hat would like to thank Chris Rohlf for reporting the CVE-2009-3608
  issue.

  This update also corrects a regression introduced in the previous poppler
  security update, RHSA-2009:0480, that prevented poppler from rendering
  certain PDF documents correctly. (BZ#528147)

  Users are advised to upgrade to these updated packages, which contain
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1504.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-3603", "CVE-2009-3608", "CVE-2009-3609");
script_summary(english: "Check for the version of the poppler packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"poppler-0.5.4-4.4.el5_4.11", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"poppler-devel-0.5.4-4.4.el5_4.11", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"poppler-utils-0.5.4-4.4.el5_4.11", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"poppler-0.5.4-4.4.el5_4.11", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"poppler-devel-0.5.4-4.4.el5_4.11", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"poppler-utils-0.5.4-4.4.el5_4.11", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
