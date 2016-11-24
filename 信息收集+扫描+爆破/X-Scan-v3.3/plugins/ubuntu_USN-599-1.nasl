# This script was automatically generated from the 599-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31848);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "599-1");
script_summary(english:"Ghostscript vulnerability");
script_name(english:"USN599-1 : Ghostscript vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gs 
- gs-esp 
- gs-esp-x 
- gs-gpl 
- libgs-esp-dev 
- libgs-esp8 
');
script_set_attribute(attribute:'description', value: 'Chris Evans discovered that Ghostscript contained a buffer overflow in
its color space handling code. If a user or automated system were
tricked into opening a crafted Postscript file, an attacker could cause
a denial of service or execute arbitrary code with privileges of the
user invoking the program. (CVE-2008-0411)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gs-8.54.dfsg.1-5ubuntu0.2 (Ubuntu 7.04)
- gs-esp-8.15.4.dfsg.1-0ubuntu1.1 (Ubuntu 7.04)
- gs-esp-x-8.15.4.dfsg.1-0ubuntu1.1 (Ubuntu 7.04)
- gs-gpl-8.54.dfsg.1-5ubuntu0.2 (Ubuntu 7.04)
- libgs-esp-dev-8.15.4.dfsg.1-0ubuntu1.1 (Ubuntu 7.04)
- libgs-esp8-8.15.4.dfsg.1-0ubuntu1.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-0411");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "gs", pkgver: "8.54.dfsg.1-5ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gs-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to gs-8.54.dfsg.1-5ubuntu0.2
');
}
found = ubuntu_check(osver: "7.04", pkgname: "gs-esp", pkgver: "8.15.4.dfsg.1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gs-esp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to gs-esp-8.15.4.dfsg.1-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "gs-esp-x", pkgver: "8.15.4.dfsg.1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gs-esp-x-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to gs-esp-x-8.15.4.dfsg.1-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "gs-gpl", pkgver: "8.54.dfsg.1-5ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gs-gpl-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to gs-gpl-8.54.dfsg.1-5ubuntu0.2
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libgs-esp-dev", pkgver: "8.15.4.dfsg.1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgs-esp-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libgs-esp-dev-8.15.4.dfsg.1-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libgs-esp8", pkgver: "8.15.4.dfsg.1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgs-esp8-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libgs-esp8-8.15.4.dfsg.1-0ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
