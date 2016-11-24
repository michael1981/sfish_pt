
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39850);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1159: libtiff");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1159");
 script_set_attribute(attribute: "description", value: '
  Updated libtiff packages that fix several security issues are now available
  for Red Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The libtiff packages contain a library of functions for manipulating Tagged
  Image File Format (TIFF) files.

  Several integer overflow flaws, leading to heap-based buffer overflows,
  were found in various libtiff color space conversion tools. An attacker
  could create a specially-crafted TIFF file, which once opened by an
  unsuspecting user, would cause the conversion tool to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the tool. (CVE-2009-2347)

  A buffer underwrite flaw was found in libtiff\'s Lempel-Ziv-Welch (LZW)
  compression algorithm decoder. An attacker could create a specially-crafted
  LZW-encoded TIFF file, which once opened by an unsuspecting user, would
  cause an application linked with libtiff to access an out-of-bounds memory
  location, leading to a denial of service (application crash).
  (CVE-2009-2285)

  The CVE-2009-2347 flaws were discovered by Tielei Wang from ICST-ERCIS,
  Peking University.

  All libtiff users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing this update,
  all applications linked with the libtiff library (such as Konqueror) must
  be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1159.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2285", "CVE-2009-2347");
script_summary(english: "Check for the version of the libtiff packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libtiff-3.8.2-7.el5_3.4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.8.2-7.el5_3.4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.5.7-33.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.5.7-33.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.6.1-12.el4_8.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.6.1-12.el4_8.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.6.1-12.el4_8.4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.6.1-12.el4_8.4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.8.2-7.el5_3.4", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.8.2-7.el5_3.4", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
