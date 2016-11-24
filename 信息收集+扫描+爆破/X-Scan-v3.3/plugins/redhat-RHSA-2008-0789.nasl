
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33865);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0789: dnsmasq");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0789");
 script_set_attribute(attribute: "description", value: '
  An updated dnsmasq package that implements UDP source-port randomization
  is now available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Dnsmasq is lightweight DNS forwarder and DHCP server. It is designed to
  provide DNS and, optionally, DHCP, to a small network.

  The dnsmasq DNS resolver used a fixed source UDP port. This could have made
  DNS spoofing attacks easier. dnsmasq has been updated to use random UDP
  source ports, helping to make DNS spoofing attacks harder. (CVE-2008-1447)

  All dnsmasq users are advised to upgrade to this updated package, that
  upgrades dnsmasq to version 2.45, which resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0789.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1447");
script_summary(english: "Check for the version of the dnsmasq packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dnsmasq-2.45-1.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
