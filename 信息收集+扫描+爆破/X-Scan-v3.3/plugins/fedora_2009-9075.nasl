
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9075
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42454);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-9075: dhcp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9075 (dhcp)");
 script_set_attribute(attribute: "description", value: "DHCP (Dynamic Host Configuration Protocol) is a protocol which allows
individual devices on an IP network to get their own network
configuration information (IP address, subnetmask, broadcast address,
etc.) from a DHCP server. The overall purpose of DHCP is to make it
easier to administer a large network.  The dhcp package includes the
ISC DHCP service and relay agent.

To use DHCP on your network, install a DHCP service (or relay agent),
and on clients run a DHCP client daemon.  The dhcp package provides
the ISC DHCP service and relay agent.

-
Update Information:

Do not require policycoreutils when installing dhcp or dhclient packages.  If
you have the package installed, the /sbin/restorecon program will be used by
dhclient-script and the dhcpd init script.    This update to the dhcp package
includes fixes for CVE-2009-0692 and CVE-2009-1892. More information on these
issues are available here:    [9]http://cve.mitre.org/cgi-
bin/cvename.cgi?name=CVE-2009-0692  [10]http://cve.mitre.org/cgi-
bin/cvename.cgi?name=CVE-2009-1892    Note: CVE-2009-0692 had no security
consequences on Fedora, thanks to the use of FORTIFY_SOURCE
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0692", "CVE-2009-1892");
script_summary(english: "Check for the version of the dhcp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"dhcp-4.1.0p1-4.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
