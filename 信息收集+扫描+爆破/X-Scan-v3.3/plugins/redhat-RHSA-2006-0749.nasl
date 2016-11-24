
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(23959);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0749: tar");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0749");
 script_set_attribute(attribute: "description", value: '
  Updated tar packages that fix a path traversal flaw are now available.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  The GNU tar program saves many files together in one archive and can
  restore individual files (or all of the files) from that archive.

  Teemu Salmela discovered a path traversal flaw in the way GNU tar extracted
  archives. A malicious user could create a tar archive that could write to
  arbitrary files to which the user running GNU tar has write access.
  (CVE-2006-6097)

  Users of tar should upgrade to this updated package, which contains a
  replacement backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0749.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-6097");
script_summary(english: "Check for the version of the tar packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tar-1.13.25-6.AS21.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tar-1.13.25-15.RHEL3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tar-1.14-12.RHEL4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
