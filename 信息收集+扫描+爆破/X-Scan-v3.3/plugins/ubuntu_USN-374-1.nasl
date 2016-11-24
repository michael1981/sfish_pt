# This script was automatically generated from the 374-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27955);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "374-1");
script_summary(english:"wvWare vulnerability");
script_name(english:"USN374-1 : wvWare vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libwv-1.2-1 
- libwv-dev 
- wv 
');
script_set_attribute(attribute:'description', value: 'An integer overflow was discovered in the DOC file parser of the wv 
library.  By tricking a user into opening a specially crafted MSWord 
(.DOC) file, remote attackers could execute arbitrary code with the 
user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libwv-1.2-1-1.2.1-2ubuntu0.1 (Ubuntu 6.10)
- libwv-dev-1.2.1-2ubuntu0.1 (Ubuntu 6.10)
- wv-1.2.1-2ubuntu0.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4513");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "libwv-1.2-1", pkgver: "1.2.1-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwv-1.2-1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libwv-1.2-1-1.2.1-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libwv-dev", pkgver: "1.2.1-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwv-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libwv-dev-1.2.1-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "wv", pkgver: "1.2.1-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package wv-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to wv-1.2.1-2ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
