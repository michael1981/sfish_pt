
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22442);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0667: gzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0667");
 script_set_attribute(attribute: "description", value: '
  Updated gzip packages that fix several security issues are now available
  for Red Hat Enterprise Linux.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The gzip package contains the GNU gzip data compression program.

  Tavis Ormandy of the Google Security Team discovered two denial of service
  flaws in the way gzip expanded archive files. If a victim expanded a
  specially crafted archive, it could cause the gzip executable to hang or
  crash. (CVE-2006-4334, CVE-2006-4338)

  Tavis Ormandy of the Google Security Team discovered several code execution
  flaws in the way gzip expanded archive files. If a victim expanded a
  specially crafted archive, it could cause the gzip executable to crash or
  execute arbitrary code. (CVE-2006-4335, CVE-2006-4336, CVE-2006-4337)

  Users of gzip should upgrade to these updated packages, which contain a
  backported patch and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0667.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4334", "CVE-2006-4335", "CVE-2006-4336", "CVE-2006-4337", "CVE-2006-4338");
script_summary(english: "Check for the version of the gzip packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gzip-1.3-19.rhel2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gzip-1.3.3-13.rhel3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gzip-1.3.3-16.rhel4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
