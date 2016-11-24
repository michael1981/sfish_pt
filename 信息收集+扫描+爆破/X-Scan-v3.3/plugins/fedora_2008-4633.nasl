
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-4633
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32469);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-4633: system-config-network");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-4633 (system-config-network)");
 script_set_attribute(attribute: "description", value: "This is the GUI of the network configuration tool,
supporting Ethernet, Wireless, TokenRing, ADSL, ISDN and PPP.

-
Update Information:

This security update fixes system-config-network-1.5.5-1.fc8, where the console
file from Fedora 9 was distributed. This bug enabled every console user to
change the network configuration.  Systems with system-config-
network-1.5.5-1.fc8 installed should install this update.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2359");
script_summary(english: "Check for the version of the system-config-network package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"system-config-network-1.5.10-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
