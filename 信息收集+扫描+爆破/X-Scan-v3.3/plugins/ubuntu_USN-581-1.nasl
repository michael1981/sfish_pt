# This script was automatically generated from the 581-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31166);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "581-1");
script_summary(english:"PCRE vulnerability");
script_name(english:"USN581-1 : PCRE vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpcre3 
- libpcre3-dev 
- libpcrecpp0 
- pcregrep 
- pgrep 
');
script_set_attribute(attribute:'description', value: 'It was discovered that PCRE did not correctly handle very long strings
containing UTF8 sequences.  In certain situations, an attacker could
exploit applications linked against PCRE by tricking a user or automated
system in processing a malicious regular expression leading to a denial
of service or possibly arbitrary code execution.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpcre3-7.4-0ubuntu0.7.10.2 (Ubuntu 7.10)
- libpcre3-dev-7.4-0ubuntu0.7.10.2 (Ubuntu 7.10)
- libpcrecpp0-7.4-0ubuntu0.7.10.2 (Ubuntu 7.10)
- pcregrep-7.4-0ubuntu0.7.10.2 (Ubuntu 7.10)
- pgrep-7.4-0ubuntu0.6.06.2 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-0674");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libpcre3", pkgver: "7.4-0ubuntu0.7.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpcre3-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpcre3-7.4-0ubuntu0.7.10.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpcre3-dev", pkgver: "7.4-0ubuntu0.7.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpcre3-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpcre3-dev-7.4-0ubuntu0.7.10.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpcrecpp0", pkgver: "7.4-0ubuntu0.7.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpcrecpp0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpcrecpp0-7.4-0ubuntu0.7.10.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pcregrep", pkgver: "7.4-0ubuntu0.7.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pcregrep-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pcregrep-7.4-0ubuntu0.7.10.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "pgrep", pkgver: "7.4-0ubuntu0.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pgrep-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to pgrep-7.4-0ubuntu0.6.06.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
