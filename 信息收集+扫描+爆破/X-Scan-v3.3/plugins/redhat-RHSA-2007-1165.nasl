
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29775);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-1165: libexif");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1165");
 script_set_attribute(attribute: "description", value: '
  Updated libexif packages that fix several security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The libexif packages contain the Exif library. Exif is an image file format
  specification that enables metadata tags to be added to existing JPEG, TIFF
  and RIFF files. The Exif library makes it possible to parse an Exif file
  and read this metadata.

  An infinite recursion flaw was found in the way libexif parses Exif image
  tags. If a victim opens a carefully crafted Exif image file, it could cause
  the application linked against libexif to crash. (CVE-2007-6351)

  An integer overflow flaw was found in the way libexif parses Exif image
  tags. If a victim opens a carefully crafted Exif image file, it could cause
  the application linked against libexif to execute arbitrary code, or crash.
  (CVE-2007-6352)

  Users of libexif are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1165.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-6351", "CVE-2007-6352");
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

if ( rpm_check( reference:"libexif-0.6.13-4.0.2.el5_1.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif-devel-0.6.13-4.0.2.el5_1.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
