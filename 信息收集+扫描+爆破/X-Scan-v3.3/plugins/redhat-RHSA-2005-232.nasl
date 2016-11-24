
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17622);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-232: ipsec");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-232");
 script_set_attribute(attribute: "description", value: '
  An updated ipsec-tools package that fixes a bug in parsing of ISAKMP
  headers
  is now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The ipsec-tools package is used in conjunction with the IPsec functionality
  in the linux kernel. The ipsec-tools package includes:

  - setkey, a program to directly manipulate policies and SAs
  - racoon, an IKEv1 keying daemon

  A bug was found in the way the racoon daemon handled incoming ISAKMP
  requests. It is possible that an attacker could crash the racoon daemon by
  sending a specially crafted ISAKMP packet. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-0398 to
  this issue.

  Additionally, the following issues have been fixed:
  - racoon mishandled restarts in the presence of stale administration
  sockets.
  - on Red Hat Enterprise Linux 4, racoon and setkey did not properly set up
  forward policies, which prevented tunnels from working.

  Users of ipsec-tools should upgrade to this updated package, which contains
  backported patches, and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-232.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0398");
script_summary(english: "Check for the version of the ipsec packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ipsec-tools-0.2.5-0.7", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-0.3.3-6", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
