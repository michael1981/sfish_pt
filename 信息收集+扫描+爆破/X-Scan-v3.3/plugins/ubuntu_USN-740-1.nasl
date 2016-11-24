# This script was automatically generated from the 740-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37463);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "740-1");
script_summary(english:"nss, firefox vulnerability");
script_name(english:"USN740-1 : nss, firefox vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libnss3-0d 
- libnss3-0d-dbg 
- libnss3-1d 
- libnss3-1d-dbg 
- libnss3-dev 
- libnss3-tools 
');
script_set_attribute(attribute:'description', value: 'The MD5 algorithm is known not to be collision resistant. This update
blacklists the proof of concept rogue certificate authority as discussed
in http://www.win.tue.nl/hashclash/rogue-ca/.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libnss3-0d-3.12.0.3-0ubuntu5.8.10.1 (Ubuntu 8.10)
- libnss3-0d-dbg-3.11.5-3ubuntu0.7.10.2 (Ubuntu 7.10)
- libnss3-1d-3.12.0.3-0ubuntu5.8.10.1 (Ubuntu 8.10)
- libnss3-1d-dbg-3.12.0.3-0ubuntu5.8.10.1 (Ubuntu 8.10)
- libnss3-dev-3.12.0.3-0ubuntu5.8.10.1 (Ubuntu 8.10)
- libnss3-tools-3.12.0.3-0ubuntu5.8.10.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2004-2761");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "libnss3-0d", pkgver: "3.12.0.3-0ubuntu5.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-0d-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libnss3-0d-3.12.0.3-0ubuntu5.8.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libnss3-0d-dbg", pkgver: "3.11.5-3ubuntu0.7.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-0d-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libnss3-0d-dbg-3.11.5-3ubuntu0.7.10.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libnss3-1d", pkgver: "3.12.0.3-0ubuntu5.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-1d-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libnss3-1d-3.12.0.3-0ubuntu5.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libnss3-1d-dbg", pkgver: "3.12.0.3-0ubuntu5.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-1d-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libnss3-1d-dbg-3.12.0.3-0ubuntu5.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libnss3-dev", pkgver: "3.12.0.3-0ubuntu5.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libnss3-dev-3.12.0.3-0ubuntu5.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libnss3-tools", pkgver: "3.12.0.3-0ubuntu5.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-tools-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libnss3-tools-3.12.0.3-0ubuntu5.8.10.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
