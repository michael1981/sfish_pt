
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40704);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2007-0696: flash");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0696");
 script_set_attribute(attribute: "description", value: '
  An updated Adobe Flash Player package that fixes a security issue is now
  available for Red Hat Enterprise Linux 3 Extras, 4 Extras, and 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The flash-plugin package contains a Firefox-compatible Adobe Flash Player
  browser plug-in.

  An input validation flaw was found in the way Flash Player displayed
  certain content. It may be possible to execute arbitrary code on a victim\'s
  machine if the victim opens a malicious Adobe Flash file. (CVE-2007-3456)

  Users of Adobe Flash Player should upgrade to this updated package, which
  contains version 9.0.47.0. and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0696.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3456");
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

if ( rpm_check( reference:"flash-plugin-9.0.48.0-1.el3.with.oss", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"flash-plugin-9.0.48.0-1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
