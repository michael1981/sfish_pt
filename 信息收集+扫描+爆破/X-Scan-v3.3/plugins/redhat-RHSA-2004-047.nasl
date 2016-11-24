
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12460);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-047: pwlib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-047");
 script_set_attribute(attribute: "description", value: '
  Updated PWLib packages that contain fixes for security issues found during
  protocol testing by the NISCC are now available.

  PWLib is a cross-platform class library designed to support the OpenH323
  project. OpenH323 provides an implementation of the ITU H.323
  teleconferencing protocol, used by packages such as Gnome Meeting.

  A test suite for the H.225 protocol (part of the H.323 family) provided by
  the NISCC uncovered bugs in PWLib prior to version 1.6.0. An attacker
  could trigger these bugs by sending carefully crafted messages to an
  application. The effects of such an attack can vary depending on the
  application, but would usually result in a Denial of Service. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0097 to this issue.

  Users are advised to upgrade to the erratum packages, which contain
  backported security fixes and are not vulnerable to these issues.

  Red Hat would like to thank Craig Southeren of the OpenH323 project for
  providing the fixes for these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-047.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0097");
script_summary(english: "Check for the version of the pwlib packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pwlib-1.4.7-7.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
