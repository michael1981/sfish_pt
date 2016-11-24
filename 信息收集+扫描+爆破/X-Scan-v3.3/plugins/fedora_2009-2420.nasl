
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2420
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35801);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-2420: NetworkManager");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2420 (NetworkManager)");
 script_set_attribute(attribute: "description", value: "NetworkManager attempts to keep an active network connection available at all
times.  It is intended only for the desktop use-case, and is not intended for
usage on servers.   The point of NetworkManager is to make networking
configuration and setup as painless and automatic as possible.  If using DHCP,
NetworkManager is _intended_ to replace default routes, obtain IP addresses
from a DHCP server, and change nameservers whenever it sees fit.

-
ChangeLog:


Update information :

* Wed Mar  4 2009 Dan Williams <dcbw redhat com> - 1:0.7.0.99-1
- nm: make default wired 'Auto ethX' connection modifiable if an enabled system
settings
plugin supports modifying connections (rh #485555)
- nm: manpage fixes (rh #447233)
- nm: CVE-2009-0365 - GetSecrets disclosure
- applet: CVE-2009-0578 - local users can modify the connection settings
- applet: fix inability to choose WPA Ad-Hoc networks from the menu
- ifcfg-rh: add read-only support for WPA-PSK connections
- ifcfg-rh: revert fix for #441453 (honor localhost) until gdm gets fixed
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0365", "CVE-2009-0578");
script_summary(english: "Check for the version of the NetworkManager package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"NetworkManager-0.7.0.99-1.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
