
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25364);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0391: file");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0391");
 script_set_attribute(attribute: "description", value: '
  An updated file package that fixes a security flaw is now available for Red
  Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The file command is used to identify a particular file according to the
  type of data contained by the file.

  The fix for CVE-2007-1536 introduced a new integer underflow flaw in the
  file utility. An attacker could create a carefully crafted file which, if
  examined by a victim using the file utility, could lead to arbitrary code
  execution. (CVE-2007-2799)

  This issue did not affect the version of the file utility distributed with
  Red Hat Enterprise Linux 2.1 or 3.

  Users should upgrade to this erratum package, which contain a backported
  patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0391.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2799");
script_summary(english: "Check for the version of the file packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"file-4.17-9.0.1.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"file-4.10-3.0.2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
