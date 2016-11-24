# This script was automatically generated from the 85-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20710);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "85-1");
script_summary(english:"gaim vulnerabilities");
script_name(english:"USN85-1 : gaim vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gaim" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'The Gaim developers discovered that the HTML parser did not
sufficiently validate its input. This allowed a remote attacker to
crash the Gaim client by sending certain malformed HTML messages.
(CVE-2005-0208, CVE-2005-0473)

Another lack of sufficient input validation was found in the "Oscar"
protocol handler which is used for ICQ and AIM. By sending specially
crafted packets, remote users could trigger an infinite loop in Gaim
which caused Gaim to become unresponsive and hang. (CVE-2005-0472)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gaim-1.0.0-1ubuntu1.2 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2005-0208","CVE-2005-0472","CVE-2005-0473");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "gaim", pkgver: "1.0.0-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gaim-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to gaim-1.0.0-1ubuntu1.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
