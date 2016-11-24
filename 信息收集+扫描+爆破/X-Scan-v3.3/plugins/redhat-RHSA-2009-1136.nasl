
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39798);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1136: dhclient");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1136");
 script_set_attribute(attribute: "description", value: '
  Updated dhcp packages that fix a security issue are now available for Red
  Hat Enterprise Linux 4 and 4.7 Extended Update Support.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The Dynamic Host Configuration Protocol (DHCP) is a protocol that allows
  individual devices on an IP network to get their own network configuration
  information, including an IP address, a subnet mask, and a broadcast
  address.

  The Mandriva Linux Engineering Team discovered a stack-based buffer
  overflow flaw in the ISC DHCP client. If the DHCP client were to receive a
  malicious DHCP response, it could crash or execute arbitrary code with the
  permissions of the client (root). (CVE-2009-0692)

  Users of DHCP should upgrade to these updated packages, which contain a
  backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1136.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0692");
script_summary(english: "Check for the version of the dhclient packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dhclient-3.0.1-65.el4_8.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-3.0.1-65.el4_8.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0.1-65.el4_8.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhclient-3.0.1-62.el4_7.1", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-3.0.1-62.el4_7.1", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0.1-62.el4_7.1", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhclient-3.0.1-65.el4_8.1", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-3.0.1-65.el4_8.1", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0.1-65.el4_8.1", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
