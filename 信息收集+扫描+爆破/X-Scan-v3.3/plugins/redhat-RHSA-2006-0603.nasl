
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22149);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0603: libtiff");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0603");
 script_set_attribute(attribute: "description", value: '
  Updated libtiff packages that fix several security flaws are now available
  for Red Hat Enterprise Linux.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The libtiff package contains a library of functions for manipulating TIFF
  (Tagged Image File Format) files.

  Tavis Ormandy of Google discovered a number of flaws in libtiff during a
  security audit. An attacker could create a carefully crafted TIFF file in
  such a way that it was possible to cause an application linked with libtiff
  to crash or possibly execute arbitrary code. (CVE-2006-3459, CVE-2006-3460,
  CVE-2006-3461, CVE-2006-3462, CVE-2006-3463, CVE-2006-3464, CVE-2006-3465)

  All users are advised to upgrade to these updated packages, which contain
  backported fixes for these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0603.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-2656", "CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");
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

if ( rpm_check( reference:"libtiff-3.5.7-30.el2.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.5.7-30.el2.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.5.7-25.el3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.5.7-25.el3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.6.1-12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.6.1-12", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
