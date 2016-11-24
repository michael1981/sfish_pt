
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38659);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-0457: libwmf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0457");
 script_set_attribute(attribute: "description", value: '
  Updated libwmf packages that fix one security issue are now available for
  Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  libwmf is a library for reading and converting Windows Metafile Format
  (WMF) vector graphics. libwmf is used by applications such as GIMP and
  ImageMagick.

  A pointer use-after-free flaw was found in the GD graphics library embedded
  in libwmf. An attacker could create a specially-crafted WMF file that would
  cause an application using libwmf to crash or, potentially, execute
  arbitrary code as the user running the application when opened by a victim.
  (CVE-2009-1364)

  Note: This flaw is specific to the GD graphics library embedded in libwmf.
  It does not affect the GD graphics library from the "gd" packages, or
  applications using it.

  Red Hat would like to thank Tavis Ormandy of the Google Security Team for
  responsibly reporting this flaw.

  All users of libwmf are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing the
  update, all applications using libwmf must be restarted for the update
  to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0457.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1364");
script_summary(english: "Check for the version of the libwmf packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libwmf-0.2.8.4-10.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwmf-devel-0.2.8.4-10.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwmf-0.2.8.3-5.8", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwmf-devel-0.2.8.3-5.8", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
