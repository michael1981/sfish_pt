
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34229);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0893: bzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0893");
 script_set_attribute(attribute: "description", value: '
  Updated bzip2 packages that fix a security issue are now available for Red
  Hat Enterprise Linux 2.1, 3, 4, and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Bzip2 is a freely available, high-quality data compressor. It provides both
  stand-alone compression and decompression utilities, as well as a shared
  library for use with other programs.

  A buffer over-read flaw was discovered in the bzip2 decompression routine.
  This issue could cause an application linked against the libbz2 library to
  crash when decompressing malformed archives. (CVE-2008-1372)

  Users of bzip2 should upgrade to these updated packages, which contain a
  backported patch to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0893.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1372");
script_summary(english: "Check for the version of the bzip packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"bzip2-1.0.3-4.el5_2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-devel-1.0.3-4.el5_2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-libs-1.0.3-4.el5_2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-1.0.1-5.EL2.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-devel-1.0.1-5.EL2.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-libs-1.0.1-5.EL2.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-1.0.2-12.EL3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-devel-1.0.2-12.EL3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-libs-1.0.2-12.EL3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-1.0.2-14.el4_7", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-devel-1.0.2-14.el4_7", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-libs-1.0.2-14.el4_7", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
