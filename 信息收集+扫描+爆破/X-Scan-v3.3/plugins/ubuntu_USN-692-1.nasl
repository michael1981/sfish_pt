# This script was automatically generated from the 692-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36984);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "692-1");
script_summary(english:"ekg, libgadu vulnerability");
script_name(english:"USN692-1 : ekg, libgadu vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ekg 
- libgadu-dev 
- libgadu3 
- libgadu3-dbg 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the Gadu library, used by some Instant Messaging
clients, did not correctly verify certain packet sizes from the server.
If a user connected to a malicious server, clients using Gadu could be
made to crash, leading to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ekg-1.6+20051103-1ubuntu1.1 (Ubuntu 6.06)
- libgadu-dev-1.8.0+r592-1ubuntu0.1 (Ubuntu 8.10)
- libgadu3-1.8.0+r592-1ubuntu0.1 (Ubuntu 8.10)
- libgadu3-dbg-1.8.0+r592-1ubuntu0.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2008-4776");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "ekg", pkgver: "1.6+20051103-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ekg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ekg-1.6+20051103-1ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libgadu-dev", pkgver: "1.8.0+r592-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgadu-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libgadu-dev-1.8.0+r592-1ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libgadu3", pkgver: "1.8.0+r592-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgadu3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libgadu3-1.8.0+r592-1ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libgadu3-dbg", pkgver: "1.8.0+r592-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgadu3-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libgadu3-dbg-1.8.0+r592-1ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
