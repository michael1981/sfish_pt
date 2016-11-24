
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15701);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2004-609: freeradius");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-609");
 script_set_attribute(attribute: "description", value: '
  Updated freeradius packages that fix a number of denial of service
  vulnerabilities as well as minor bugs are now available for Red Hat
  Enterprise Linux 3.

  FreeRADIUS is a high-performance and highly configurable free RADIUS server
  designed to allow centralized authentication and authorization for a
  network.

  A number of flaws were found in FreeRADIUS versions prior to 1.0.1. An
  attacker who is able to send packets to the server could construct
  carefully constructed packets in such a way as to cause the server to
  consume memory or crash. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the names CAN-2004-0938, CAN-2004-0960, and
  CAN-2004-0961 to these issues.

  Users of FreeRADIUS should update to these erratum packages that contain
  FreeRADIUS 1.0.1, which is not vulnerable to these issues and also corrects
  a number of bugs.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-609.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0938", "CVE-2004-0960", "CVE-2004-0961");
script_summary(english: "Check for the version of the freeradius packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"freeradius-1.0.1-1.RHEL3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
