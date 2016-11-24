
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42430);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1526: redhat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1526");
 script_set_attribute(attribute: "description", value: '
  This is the 1-year notification of the End Of Life plans for Red Hat
  Enterprise Linux 3.

  In accordance with the Red Hat Enterprise Linux Errata Support Policy, the
  regular 7 year life-cycle of Red Hat Enterprise Linux 3 will end on October
  31, 2010.

  After this date, Red Hat will discontinue the regular subscription services
  for Red Hat Enterprise Linux 3. Therefore, new bug fix, enhancement, and
  security errata updates, as well as technical support services will no
  longer be available for the following products:

  * Red Hat Enterprise Linux AS 3
  * Red Hat Enterprise Linux ES 3
  * Red Hat Enterprise Linux WS 3
  * Red Hat Enterprise Linux Extras 3
  * Red Hat Desktop 3
  * Red Hat Global File System 3
  * Red Hat Cluster Suite 3

  Customers still running production workloads on Red Hat Enterprise
  Linux 3 are advised to begin planning the upgrade to Red Hat Enterprise
  Linux 5. Active subscribers of Red Hat Enterprise Linux already have access
  to all currently maintained versions of Red Hat Enterprise Linux, as part
  of their subscription without additional fees.

  For customers who are unable to migrate off Red Hat Enterprise Linux 3
  before its end-of-life date, Red Hat may offer a limited, optional
  extension program. For more information, contact your Red Hat sales
  representative or channel partner.

  Details of the Red Hat Enterprise Linux life-cycle can be found on the Red
  Hat website: http://www.redhat.com/security/updates/errata/


');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1526.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_summary(english: "Check for the version of the redhat packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"redhat-release-3AS-13.9.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"redhat-release-3ES-13.9.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"redhat-release-3WS-13.9.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
