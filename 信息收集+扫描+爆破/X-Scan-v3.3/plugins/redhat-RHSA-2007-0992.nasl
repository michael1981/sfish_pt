
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27571);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0992: libpng");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0992");
 script_set_attribute(attribute: "description", value: '
  Updated libpng packages that fix security issues are now available for Red
  Hat Enterprise Linux.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The libpng package contains a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  Several flaws were discovered in the way libpng handled various PNG image
  chunks. An attacker could create a carefully crafted PNG image file in
  such a way that it could cause an application linked with libpng to crash
  when the file was manipulated. (CVE-2007-5269)

  Users should update to these updated packages which contain a backported
  patch to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0992.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5269");
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

if ( rpm_check( reference:"libpng-1.2.10-7.1.el5_0.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.10-7.1.el5_0.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-1.0.14-11", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.0.14-11", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.2-28", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.2-28", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng10-1.0.13-18", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng10-devel-1.0.13-18", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.7-3.el4_5.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.7-3.el4_5.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng10-1.0.16-3.el4_5.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng10-devel-1.0.16-3.el4_5.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
