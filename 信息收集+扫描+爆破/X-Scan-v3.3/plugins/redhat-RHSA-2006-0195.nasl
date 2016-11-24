
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20965);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0195: tar");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0195");
 script_set_attribute(attribute: "description", value: '
  An updated tar package that fixes a path traversal flaw is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The GNU tar program saves many files together in one archive and can
  restore individual files (or all of the files) from that archive.

  In 2002, a path traversal flaw was found in the way GNU tar extracted
  archives. A malicious user could create a tar archive that could write to
  arbitrary files to which the user running GNU tar has write access
  (CVE-2002-0399). Red Hat included a backported security patch to correct
  this issue in Red Hat Enterprise Linux 3, and an erratum for Red Hat
  Enterprise Linux 2.1 users was issued.

  During internal testing, we discovered that our backported security patch
  contained an incorrect optimization and therefore was not sufficient to
  completely correct this vulnerability. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) assigned the name CVE-2005-1918 to this
  issue.

  Users of tar should upgrade to this updated package, which contains a
  replacement backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0195.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1918");
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

if ( rpm_check( reference:"tar-1.13.25-5.AS21.1", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tar-1.13.25-14.RHEL3", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
