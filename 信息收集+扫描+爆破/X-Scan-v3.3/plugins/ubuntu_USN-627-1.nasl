# This script was automatically generated from the 627-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33560);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "627-1");
script_summary(english:"Dnsmasq vulnerability");
script_name(english:"USN627-1 : Dnsmasq vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- dnsmasq 
- dnsmasq-base 
');
script_set_attribute(attribute:'description', value: 'Dan Kaminsky discovered weaknesses in the DNS protocol as implemented
by Dnsmasq. A remote attacker could exploit this to spoof DNS entries
and poison DNS caches. Among other things, this could lead to
misdirected email and web traffic.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- dnsmasq-2.41-2ubuntu2.1 (Ubuntu 8.04)
- dnsmasq-base-2.41-2ubuntu2.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-1447");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "dnsmasq", pkgver: "2.41-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dnsmasq-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to dnsmasq-2.41-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "dnsmasq-base", pkgver: "2.41-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dnsmasq-base-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to dnsmasq-base-2.41-2ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
