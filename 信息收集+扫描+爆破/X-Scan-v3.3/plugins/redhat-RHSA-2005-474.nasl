
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18510);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-474: bzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-474");
 script_set_attribute(attribute: "description", value: '
  Updated bzip2 packages that fix multiple issues are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  [Updated 13 February 2006]
  Replacement bzip2 packages for Red Hat Enterprise Linux 4 have been created
  as the original erratum packages did not fix CVE-2005-0758.

  Bzip2 is a data compressor.

  A bug was found in the way bzgrep processes file names. If a user can be
  tricked into running bzgrep on a file with a carefully crafted file name,
  arbitrary commands could be executed as the user running bzgrep. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0758 to this issue.

  A bug was found in the way bzip2 modifies file permissions during
  decompression. If an attacker has write access to the directory into which
  bzip2 is decompressing files, it is possible for them to modify permissions
  on files owned by the user running bzip2 (CVE-2005-0953).

  A bug was found in the way bzip2 decompresses files. It is possible for an
  attacker to create a specially crafted bzip2 file which will cause bzip2 to
  cause a denial of service (by filling disk space) if decompressed by a
  victim (CVE-2005-1260).

  Users of Bzip2 should upgrade to these updated packages, which contain
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-474.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0758", "CVE-2005-0953", "CVE-2005-1260");
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

if ( rpm_check( reference:"bzip2-1.0.1-4.EL2.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-devel-1.0.1-4.EL2.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-libs-1.0.1-4.EL2.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-1.0.2-11.EL3.4", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-devel-1.0.2-11.EL3.4", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-libs-1.0.2-11.EL3.4", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-1.0.2-13.EL4.3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-devel-1.0.2-13.EL4.3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-libs-1.0.2-13.EL4.3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
