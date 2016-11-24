
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18018);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2005-212: dhcp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-212");
 script_set_attribute(attribute: "description", value: '
  An updated dhcp package that fixes a string format issue is now available
  for Red Hat Enterprise Linux 2.1.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The dhcp package provides the ISC Dynamic Host Configuration Protocol
  (DHCP) server and relay agent, dhcpd. DHCP is a protocol that allows
  devices to get their own network configuration information from a server.

  A bug was found in the way dhcpd logs error messages. A malicious DNS
  server could send a carefully crafted DNS reply and cause dhcpd to crash or
  possibly execute arbitrary code. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2005-0446 to this issue.

  All users of dhcp should upgrade to this updated package, which contains a
  backported patch and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-212.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1006");
script_summary(english: "Check for the version of the dhcp packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dhcp-2.0pl5-9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
