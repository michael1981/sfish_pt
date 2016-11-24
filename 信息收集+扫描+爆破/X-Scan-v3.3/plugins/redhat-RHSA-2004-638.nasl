
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15995);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2004-638: gd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-638");
 script_set_attribute(attribute: "description", value: '
  Updated gd packages that fix security issues with overflow in various
  memory allocation calls are now available.

  [Updated 24 May 2005]
  Multilib packages have been added to this advisory

  The gd packages contain a graphics library used for the dynamic creation of
  images such as PNG and JPEG.

  Several buffer overflows were reported in various memory allocation calls.
  An attacker could create a carefully crafted image file in such a way that
  it could cause ImageMagick to execute arbitrary code when processing the
  image. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2004-0990 to these issues.

  While researching the fixes to these overflows, additional buffer overflows
  were discovered in calls to gdMalloc. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-0941 to
  these issues.

  Users of gd should upgrade to these updated packages, which contain a
  backported security patch, and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-638.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0941", "CVE-2004-0990");
script_summary(english: "Check for the version of the gd packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gd-1.8.4-4.21.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gd-devel-1.8.4-4.21.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gd-progs-1.8.4-4.21.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gd-1.8.4-12.3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gd-devel-1.8.4-12.3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gd-progs-1.8.4-12.3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
