
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35652);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0012: netpbm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0012");
 script_set_attribute(attribute: "description", value: '
  Updated netpbm packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The netpbm package contains a library of functions for editing and
  converting between various graphics file formats, including .pbm (portable
  bitmaps), .pgm (portable graymaps), .pnm (portable anymaps), .ppm (portable
  pixmaps), and others.

  An input validation flaw and multiple integer overflows were discovered in
  the JasPer library providing support for JPEG-2000 image format and used in
  the jpeg2ktopam and pamtojpeg2k converters. An attacker could create a
  carefully-crafted JPEG file which could cause jpeg2ktopam to crash or,
  possibly, execute arbitrary code as the user running jpeg2ktopam.
  (CVE-2007-2721, CVE-2008-3520)

  All users are advised to upgrade to these updated packages which contain
  backported patches which resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0012.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2721", "CVE-2008-3520");
script_summary(english: "Check for the version of the netpbm packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"netpbm-10.35-6.1.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-10.35-6.1.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-10.35-6.1.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-10.25-2.1.el4_7.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-10.25-2.1.el4_7.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-10.25-2.1.el4_7.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
