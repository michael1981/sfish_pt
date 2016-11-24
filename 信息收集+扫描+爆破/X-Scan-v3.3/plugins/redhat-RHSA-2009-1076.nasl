
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38983);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1076: redhat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1076");
 script_set_attribute(attribute: "description", value: '
  This is the End Of Life notification for Red Hat Enterprise Linux 2.1.

  In accordance with the Red Hat Enterprise Linux Errata Support Policy, the
  7 year life-cycle of Red Hat Enterprise Linux 2.1 has ended.

  Red Hat has discontinued the technical support services, bug fix,
  enhancement, and security errata updates for the following versions:

  * Red Hat Enterprise Linux AS 2.1
  * Red Hat Enterprise Linux ES 2.1
  * Red Hat Enterprise Linux WS 2.1
  * Red Hat Linux Advanced Server 2.1
  * Red Hat Linux Advanced Workstation 2.1

  Servers subscribed to Red Hat Enterprise Linux 2.1 channels on the Red Hat
  Network will become unsubscribed. As a benefit of the Red Hat subscription
  model, those subscriptions can be used to entitle any system on any
  currently supported release of Red Hat Enterprise Linux. Details of the Red
  Hat Enterprise Linux life-cycle for all releases can be found on the Red
  Hat website:

  http://www.redhat.com/security/updates/errata/

  As part of the End Of Life process, the Red Hat Network will cease to carry
  the Red Hat Enterprise Linux 2.1 binaries. The source code and security
  advisories will continue to be available.


');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1076.html");
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

if ( rpm_check( reference:"redhat-release-as-2.1AS-25", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"redhat-release-es-2.1ES-25", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"redhat-release-ws-2.1WS-25", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
