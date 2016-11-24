
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35775);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0333: libpng");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0333");
 script_set_attribute(attribute: "description", value: '
  Updated libpng and libpng10 packages that fix a couple of security issues
  are now available for Red Hat Enterprise Linux 2.1, 4, and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The libpng packages contain a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  A flaw was discovered in libpng that could result in libpng trying to
  free() random memory if certain, unlikely error conditions occurred. If a
  carefully-crafted PNG file was loaded by an application linked against
  libpng, it could cause the application to crash or, potentially, execute
  arbitrary code with the privileges of the user running the application.
  (CVE-2009-0040)

  A flaw was discovered in the way libpng handled PNG images containing
  "unknown" chunks. If an application linked against libpng attempted to
  process a malformed, unknown chunk in a malicious PNG image, it could cause
  the application to crash. (CVE-2008-1382)

  Users of libpng and libpng10 should upgrade to these updated packages,
  which contain backported patches to correct these issues. All running
  applications using libpng or libpng10 must be restarted for the update to
  take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0333.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1382", "CVE-2009-0040");
script_summary(english: "Check for the version of the libpng packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libpng-1.2.10-7.1.el5_3.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.10-7.1.el5_3.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-1.0.14-12", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.0.14-12", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.7-3.el4_7.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.7-3.el4_7.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng10-1.0.16-3.el4_7.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng10-devel-1.0.16-3.el4_7.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
