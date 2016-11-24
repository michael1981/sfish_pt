
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40736);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2008-1047: flash");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-1047");
 script_set_attribute(attribute: "description", value: '
  An updated Adobe Flash Player package that fixes a security issue is
  now available for Red Hat Enterprise Linux 3 Extras, Red Hat Enterprise
  Linux 4 Extras, and Red Hat Enterprise Linux 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The flash-plugin package contains a Firefox-compatible Adobe Flash Player
  Web browser plug-in.

  A security flaw was found in the way Flash Player displayed certain SWF
  (Shockwave Flash) content. This may have made it possible to execute
  arbitrary code on a victim\'s machine, if the victim opened a malicious
  Adobe Flash file. (CVE-2008-5499)

  All users of Adobe Flash Player should install this updated package, which
  upgrades Flash Player to version 10.0.15.3 for users of Red Hat Enterprise
  Linux 5 Supplementary, and 9.0.152.0 for users of Red Hat Enterprise 3 and
  4 Extras.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-1047.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-5499");
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

if ( rpm_check( reference:"flash-plugin-9.0.152.0-1.el3.with.oss", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"flash-plugin-9.0.152.0-1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
