
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20753);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2006-0184: kdelibs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0184");
 script_set_attribute(attribute: "description", value: '
  Updated kdelibs packages are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  kdelibs contains libraries for the K Desktop Environment (KDE).

  A heap overflow flaw was discovered affecting kjs, the JavaScript
  interpreter engine used by Konqueror and other parts of KDE. An attacker
  could create a malicious web site containing carefully crafted JavaScript
  code that would trigger this flaw and possibly lead to arbitrary code
  execution. The Common Vulnerabilities and Exposures project assigned the
  name CVE-2006-0019 to this issue.

  NOTE: this issue does not affect KDE in Red Hat Enterprise Linux 3 or 2.1.

  Users of KDE should upgrade to these updated packages, which contain a
  backported patch from the KDE security team correcting this issue as well
  as two bug fixes.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0184.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-0019");
script_summary(english: "Check for the version of the kdelibs packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdelibs-3.3.1-3.14", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.3.1-3.14", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
