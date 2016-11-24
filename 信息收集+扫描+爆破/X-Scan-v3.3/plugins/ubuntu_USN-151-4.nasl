# This script was automatically generated from the 151-4 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20552);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "151-4");
script_summary(english:"rpm vulnerability");
script_name(english:"USN151-4 : rpm vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- librpm-dev 
- librpm4 
- lsb-rpm 
- rpm 
');
script_set_attribute(attribute:'description', value: 'USN-148-1 and USN-151-1 fixed two security flaws in zlib, which could
be exploited to cause Denial of Service attacks or even arbitrary code
execution with malicious data streams.

Since lsb-rpm is statically linked against the zlib library, it is also
affected by these issues. The updated packagages have been rebuilt
against the fixed zlib.

Please note that lsb-rpm is not officially supported (it is in the "universe"
component of the archive).');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- librpm-dev-4.0.4-31ubuntu1.1 (Ubuntu 5.10)
- librpm4-4.0.4-31ubuntu1.1 (Ubuntu 5.10)
- lsb-rpm-4.0.4-31ubuntu1.1 (Ubuntu 5.10)
- rpm-4.0.4-31ubuntu1.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-1849","CVE-2005-2096");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "librpm-dev", pkgver: "4.0.4-31ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package librpm-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to librpm-dev-4.0.4-31ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "librpm4", pkgver: "4.0.4-31ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package librpm4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to librpm4-4.0.4-31ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "lsb-rpm", pkgver: "4.0.4-31ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lsb-rpm-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to lsb-rpm-4.0.4-31ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "rpm", pkgver: "4.0.4-31ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package rpm-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to rpm-4.0.4-31ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
