# This script was automatically generated from the 67-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20687);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "67-1");
script_summary(english:"squid vulnerabilities");
script_name(english:"USN67-1 : squid vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- squid 
- squid-cgi 
- squid-common 
- squidclient 
');
script_set_attribute(attribute:'description', value: 'infamous41md discovered several Denial of Service vulnerabilities in
squid.

A malicious Gopher server could crash squid by sending a line bigger
than 4096 bytes. (CVE-2005-0094)

If squid is configured to send WCPP (Web Cache Communication Protocol)
messages to a "home router", an attacker who was able to send UDP
packets with a forged source address of this router could crash the

erver with a specially crafted WCPP message. (CVE-2005-0095)

Previous versions of squid have a memory leak which gradually cause
memory exhaustion and eventual termination. (CVE-2005-0096)

A remote attacker could crash the server by sending a specially
crafted NTLM type 3 packet. (CVE-2005-0097)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- squid-2.5.5-6ubuntu0.3 (Ubuntu 4.10)
- squid-cgi-2.5.5-6ubuntu0.3 (Ubuntu 4.10)
- squid-common-2.5.5-6ubuntu0.3 (Ubuntu 4.10)
- squidclient-2.5.5-6ubuntu0.3 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2005-0094","CVE-2005-0095","CVE-2005-0096","CVE-2005-0097");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "squid", pkgver: "2.5.5-6ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package squid-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-2.5.5-6ubuntu0.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squid-cgi", pkgver: "2.5.5-6ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package squid-cgi-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-cgi-2.5.5-6ubuntu0.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squid-common", pkgver: "2.5.5-6ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package squid-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-common-2.5.5-6ubuntu0.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squidclient", pkgver: "2.5.5-6ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package squidclient-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squidclient-2.5.5-6ubuntu0.3
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
