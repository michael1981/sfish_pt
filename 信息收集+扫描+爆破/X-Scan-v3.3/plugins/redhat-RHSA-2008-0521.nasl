
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33087);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2008-0521: redhat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0521");
 script_set_attribute(attribute: "description", value: '
  This is the 1-year notification of the End Of Life plans for Red Hat
  Enterprise Linux 2.1.

  In accordance with the Red Hat Enterprise Linux Errata Support Policy, the
  7 year life-cycle of Red Hat Enterprise Linux 2.1 will end on May 31, 2009.

  After this date, Red Hat will discontinue the technical support services,
  bug fix, enhancement, and security errata updates for the following
  products:

  * Red Hat Enterprise Linux AS 2.1
  * Red Hat Enterprise Linux ES 2.1
  * Red Hat Enterprise Linux WS 2.1
  * Red Hat Linux Advanced Server 2.1
  * Red Hat Linux Advanced Workstation 2.1

  Customers still running production workloads on Red Hat Enterprise Linux
  2.1 are advised to begin planning the upgrade to Red Hat Enterprise Linux
  5. Active subscribers of Red Hat Enterprise Linux already have access to
  all currently maintained versions of Red Hat Enterprise Linux, as part of
  their subscription.

  Details of the Red Hat Enterprise Linux life-cycle can be found on the
  Red Hat website: http://www.redhat.com/security/updates/errata/


');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0521.html");
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

if ( rpm_check( reference:"redhat-release-as-2.1AS-23", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"redhat-release-es-2.1ES-23", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"redhat-release-ws-2.1WS-23", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
