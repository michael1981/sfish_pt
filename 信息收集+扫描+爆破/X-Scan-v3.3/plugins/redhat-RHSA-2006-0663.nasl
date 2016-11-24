
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22345);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0663: ncompress");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0663");
 script_set_attribute(attribute: "description", value: '
  Updated ncompress packages that address a security issue and fix bugs are
  now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The ncompress package contains file compression and decompression
  utilities, which are compatible with the original UNIX compress utility (.Z
  file extensions).

  Tavis Ormandy of the Google Security Team discovered a lack of bounds
  checking in ncompress. An attacker could create a carefully crafted file
  that could execute arbitrary code if uncompressed by a victim.
  (CVE-2006-1168)

  In addition, two bugs that affected Red Hat Enterprise Linux 4 ncompress
  packages were fixed:

  * The display statistics and compression results in verbose mode were not
  shown when operating on zero length files.

  * An attempt to compress zero length files resulted in an unexpected return
  code.

  Users of ncompress are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0663.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-1168");
script_summary(english: "Check for the version of the ncompress packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ncompress-4.2.4-38.rhel2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ncompress-4.2.4-39.rhel3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ncompress-4.2.4-43.rhel4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
