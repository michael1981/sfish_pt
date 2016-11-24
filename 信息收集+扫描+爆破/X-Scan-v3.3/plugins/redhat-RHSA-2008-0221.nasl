
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40719);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2008-0221: flash");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0221");
 script_set_attribute(attribute: "description", value: '
  An updated Adobe Flash Player package that fixes several security issues is
  now available for Red Hat Enterprise Linux 3 Extras, Red Hat Enterprise
  Linux 4 Extras, and Red Hat Enterprise Linux 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The flash-plugin package contains a Firefox-compatible Adobe Flash Player
  Web browser plug-in.

  Several input validation flaws were found in the way Flash Player displayed
  certain content. These may have made it possible to execute arbitrary code
  on a victim\'s machine, if the victim opened a malicious Adobe Flash file.
  (CVE-2007-0071, CVE-2007-6019)

  A flaw was found in the way Flash Player established TCP sessions to remote
  hosts. A remote attacker could, consequently, use Flash Player to conduct a
  DNS rebinding attack. (CVE-2007-5275, CVE-2008-1655)

  A flaw was found in the way Flash Player restricted the interpretation and
  usage of cross-domain policy files. A remote attacker could use Flash
  Player to conduct cross-domain and cross-site scripting attacks.
  (CVE-2007-6243, CVE-2008-1654)

  A flaw was found in the way Flash Player interacted with web browsers. An
  attacker could use malicious content presented by Flash Player to conduct a
  cross-site scripting attack. (CVE-2007-6637)

  All users of Adobe Flash Player should upgrade to this updated package,
  which contains Flash Player version 9.0.124.0 and resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0221.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-0071", "CVE-2007-5275", "CVE-2007-6019", "CVE-2007-6243", "CVE-2007-6637", "CVE-2008-1654", "CVE-2008-1655", "CVE-2008-3872");
script_summary(english: "Check for the version of the flash packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"flash-plugin-9.0.124.0-1.el3.with.oss", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"flash-plugin-9.0.124.0-1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
