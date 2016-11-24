
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18390);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-473: lesstif");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-473");
 script_set_attribute(attribute: "description", value: '
  Updated lesstif packages that fix flaws in the Xpm library are now
  available for Red Hat Enterprise Linux 2.1.

  This update has been rated as having Moderate security impact by the Red
  Hat Security Response Team.

  LessTif provides libraries which implement the Motif industry standard
  graphical user interface.

  An integer overflow flaw was found in libXpm; a vulnerable version of this
  library is found within LessTif. An attacker could create a malicious XPM
  file that would execute arbitrary code if opened by a victim using an
  application linked to LessTif. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2005-0605 to this issue.

  Users of LessTif should upgrade to these updated packages, which contain a
  backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-473.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0605");
script_summary(english: "Check for the version of the lesstif packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lesstif-0.93.15-4.AS21.5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lesstif-devel-0.93.15-4.AS21.5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
