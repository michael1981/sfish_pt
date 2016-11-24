# This script was automatically generated from the 729-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37504);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "729-1");
script_summary(english:"python-crypto vulnerability");
script_name(english:"USN729-1 : python-crypto vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- python-crypto 
- python-crypto-dbg 
- python2.4-crypto 
');
script_set_attribute(attribute:'description', value: 'Mike Wiacek discovered that the ARC2 implementation in Python Crypto
did not correctly check the key length.  If a user or automated system
were tricked into processing a malicious ARC2 stream, a remote attacker
could execute arbitrary code or crash the application using Python Crypto,
leading to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- python-crypto-2.0.1+dfsg1-2.3ubuntu0.1 (Ubuntu 8.10)
- python-crypto-dbg-2.0.1+dfsg1-2.3ubuntu0.1 (Ubuntu 8.10)
- python2.4-crypto-2.0.1+dfsg1-1ubuntu1.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0544");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "python-crypto", pkgver: "2.0.1+dfsg1-2.3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-crypto-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to python-crypto-2.0.1+dfsg1-2.3ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "python-crypto-dbg", pkgver: "2.0.1+dfsg1-2.3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-crypto-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to python-crypto-dbg-2.0.1+dfsg1-2.3ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-crypto", pkgver: "2.0.1+dfsg1-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-crypto-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-crypto-2.0.1+dfsg1-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
