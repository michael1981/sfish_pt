
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12432);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-317: iproute");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-317");
 script_set_attribute(attribute: "description", value: '
  Updated iproute packages that close a locally-exploitable denial of service
  vulnerability are now available.

  The iproute package contains advanced IP routing and network device
  configuration tools.

  Herbert Xu reported that iproute can accept spoofed messages sent on the
  kernel netlink interface by other users on the local machine. This could
  lead to a local denial of service attack. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2003-0856 to
  this issue.

  Users of iproute should upgrade to these erratum packages, which contain a
  patch that checks that netlink messages actually came from the kernel.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-317.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0856");
script_summary(english: "Check for the version of the iproute packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"iproute-2.4.7-7.AS21.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"iproute-2.4.7-11.30E.1", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
