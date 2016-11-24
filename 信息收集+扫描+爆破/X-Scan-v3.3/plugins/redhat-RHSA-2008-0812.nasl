
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40726);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2008-0812: realplayer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0812");
 script_set_attribute(attribute: "description", value: '
  RealPlayer 10.0.9 as shipped in Red Hat Enterprise Linux 3 Extras, 4
  Extras, and 5 Supplementary, contains a security flaw and should not be
  used.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  [Updated 17 September 2008]
  We have updated this erratum to include packages which remove RealPlayer
  from Red Hat Enterprise Linux 3 Extras, 4 Extras and 5 Supplementary.

  RealPlayer is a media player that provides media playback locally and via
  streaming.

  RealPlayer 10.0.9 is vulnerable to a critical security flaw and should no
  longer be used. A remote attacker could leverage this flaw to execute
  arbitrary code as the user running RealPlayer. (CVE-2007-5400)

  This issue is addressed in RealPlayer 11. Red Hat is unable to ship
  RealPlayer 11 due to additional proprietary codecs included in that
  version. Therefore, users who wish to continue to use RealPlayer should get
  an update directly from www.real.com.

  This update removes the RealPlayer 10.0.9 packages due to their known
  security vulnerabilities.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0812.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5400");
script_summary(english: "Check for the version of the realplayer packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"realplayer-uninstall-10.0.9-0.rhel3.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"RealPlayer-uninstall-10.0.9-3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"RealPlayer-uninstall-10.0.9-3", release:'RHEL4.6.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
