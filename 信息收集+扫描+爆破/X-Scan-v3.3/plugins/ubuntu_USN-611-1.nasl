# This script was automatically generated from the 611-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32191);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "611-1");
script_summary(english:"Speex vulnerability");
script_name(english:"USN611-1 : Speex vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libspeex-dev 
- libspeex1 
- speex 
- speex-doc 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Speex did not properly validate its input when
processing Speex file headers. If a user or automated system were
tricked into opening a specially crafted Speex file, an attacker could
create a denial of service in applications linked against Speex or
possibly execute arbitrary code as the user invoking the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libspeex-dev-1.1.12-3ubuntu0.8.04.1 (Ubuntu 8.04)
- libspeex1-1.1.12-3ubuntu0.8.04.1 (Ubuntu 8.04)
- speex-1.1.12-3ubuntu0.8.04.1 (Ubuntu 8.04)
- speex-doc-1.1.12-3ubuntu0.8.04.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1686");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "libspeex-dev", pkgver: "1.1.12-3ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libspeex-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libspeex-dev-1.1.12-3ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libspeex1", pkgver: "1.1.12-3ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libspeex1-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libspeex1-1.1.12-3ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "speex", pkgver: "1.1.12-3ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package speex-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to speex-1.1.12-3ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "speex-doc", pkgver: "1.1.12-3ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package speex-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to speex-doc-1.1.12-3ubuntu0.8.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
