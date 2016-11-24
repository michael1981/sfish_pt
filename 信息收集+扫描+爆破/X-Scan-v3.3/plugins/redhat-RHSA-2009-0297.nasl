
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35757);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-0297: redhat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0297");
 script_set_attribute(attribute: "description", value: '
  This is the 3-month notification of the End Of Life plans for Red Hat
  Enterprise Linux 2.1.

  In accordance with the Red Hat Enterprise Linux Errata Support Policy, the
  7 years life-cycle of Red Hat Enterprise Linux 2.1 will end on May 31 2009.

  After that date, Red Hat will discontinue the technical support services,
  bugfix, enhancement and security errata updates for the following products:

  * Red Hat Enterprise Linux AS 2.1
  * Red Hat Enterprise Linux ES 2.1
  * Red Hat Enterprise Linux WS 2.1
  * Red Hat Linux Advanced Server 2.1
  * Red Hat Linux Advanced Workstation 2.1

  Customers running production workloads on Enterprise Linux 2.1 should plan
  to migrate to a later version before May 31, 2009. One benefit of a Red
  Hat subscription is the right to upgrade to never versions of Enterprise
  Linux for no extra cost. As an Enterprise Linux subscriber, you have the
  option of migrating to the following supported versions:

  * version 3 (Generally Available: Oct 2003, End-Of-Life: Oct 2010)
  * version 4 (GA: Feb 2005, EOL: Feb 2012)
  * version 5 (GA: Mar 2007, EOL: Mar 2014)

  These supported versions of Enterprise Linux are available for download
  from Red Hat Network.

  For those customers who cannot migrate from Enterprise Linux 2.1 before its
  end-of-life date, Red Hat will offer limited extended support contracts.
  For more information, contact your Red Hat sales representative.

  Details of the Red Hat Enterprise Linux life-cycle can be found on the Red
  Hat website: http://www.redhat.com/security/updates/errata/


');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0297.html");
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

if ( rpm_check( reference:"redhat-release-as-2.1AS-24", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"redhat-release-es-2.1ES-24", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"redhat-release-ws-2.1WS-24", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
