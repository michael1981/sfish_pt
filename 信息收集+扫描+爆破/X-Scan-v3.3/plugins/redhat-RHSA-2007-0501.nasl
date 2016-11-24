
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25540);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2007-0501: libexif");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0501");
 script_set_attribute(attribute: "description", value: '
  Updated libexif packages that fix an integer overflow flaw are now
  available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red Hat
  Security Response Team.

  The libexif package contains the EXIF library. Applications use this
  library to parse EXIF image files.

  An integer overflow flaw was found in the way libexif parses EXIF image
  tags. If a victim opens a carefully crafted EXIF image file it could cause
  the application linked against libexif to execute arbitrary code or crash.
  (CVE-2007-4168)

  Users of libexif should upgrade to these updated packages, which contain a
  backported patch and are not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0501.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

 script_cve_id("CVE-2006-4168");
script_summary(english: "Check for the version of the libexif packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libexif-0.6.13-4.0.2.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif-devel-0.6.13-4.0.2.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif-0.5.12-5.1.0.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif-devel-0.5.12-5.1.0.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif-0.6.13-4.0.2.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif-0.5.12-5.1.0.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif-devel-0.5.12-5.1.0.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif-0.5.12-5.1.0.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif-devel-0.5.12-5.1.0.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
