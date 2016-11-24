# This script was automatically generated from the 790-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39515);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "790-1");
script_summary(english:"cyrus-sasl2 vulnerability");
script_name(english:"USN790-1 : cyrus-sasl2 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- cyrus-sasl2-dbg 
- cyrus-sasl2-doc 
- libsasl2 
- libsasl2-2 
- libsasl2-dev 
- libsasl2-modules 
- libsasl2-modules-gssapi-heimdal 
- libsasl2-modules-gssapi-mit 
- libsasl2-modules-ldap 
- libsasl2-modules-otp 
- libsasl2-modules-sql 
- sasl2-bin 
');
script_set_attribute(attribute:'description', value: 'James Ralston discovered that the Cyrus SASL base64 encoding function
could be used unsafely.  If a remote attacker sent a specially crafted
request to a service that used SASL, it could lead to a loss of privacy,
or crash the application, resulting in a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- cyrus-sasl2-dbg-2.1.22.dfsg1-23ubuntu3.1 (Ubuntu 9.04)
- cyrus-sasl2-doc-2.1.22.dfsg1-23ubuntu3.1 (Ubuntu 9.04)
- libsasl2-2.1.22.dfsg1-18ubuntu2.1 (Ubuntu 8.04)
- libsasl2-2-2.1.22.dfsg1-23ubuntu3.1 (Ubuntu 9.04)
- libsasl2-dev-2.1.22.dfsg1-23ubuntu3.1 (Ubuntu 9.04)
- libsasl2-modules-2.1.22.dfsg1-23ubuntu3.1 (Ubuntu 9.04)
- libsasl2-modules-gssapi-heimdal-2.1.19.dfsg1-0.1ubuntu3.1 (Ubuntu 6.06)
- libsasl2-modules-gssapi-mit-2.1.22.dfsg1-23ubuntu3.1 (Ubuntu 9.04)
- libsasl2-modules-ldap-2.
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-0688");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "cyrus-sasl2-dbg", pkgver: "2.1.22.dfsg1-23ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cyrus-sasl2-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cyrus-sasl2-dbg-2.1.22.dfsg1-23ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "cyrus-sasl2-doc", pkgver: "2.1.22.dfsg1-23ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cyrus-sasl2-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cyrus-sasl2-doc-2.1.22.dfsg1-23ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libsasl2", pkgver: "2.1.22.dfsg1-18ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsasl2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libsasl2-2.1.22.dfsg1-18ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsasl2-2", pkgver: "2.1.22.dfsg1-23ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsasl2-2-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsasl2-2-2.1.22.dfsg1-23ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsasl2-dev", pkgver: "2.1.22.dfsg1-23ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsasl2-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsasl2-dev-2.1.22.dfsg1-23ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsasl2-modules", pkgver: "2.1.22.dfsg1-23ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsasl2-modules-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsasl2-modules-2.1.22.dfsg1-23ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libsasl2-modules-gssapi-heimdal", pkgver: "2.1.19.dfsg1-0.1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsasl2-modules-gssapi-heimdal-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libsasl2-modules-gssapi-heimdal-2.1.19.dfsg1-0.1ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsasl2-modules-gssapi-mit", pkgver: "2.1.22.dfsg1-23ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsasl2-modules-gssapi-mit-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsasl2-modules-gssapi-mit-2.1.22.dfsg1-23ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsasl2-modules-ldap", pkgver: "2.1.22.dfsg1-23ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsasl2-modules-ldap-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsasl2-modules-ldap-2.1.22.dfsg1-23ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsasl2-modules-otp", pkgver: "2.1.22.dfsg1-23ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsasl2-modules-otp-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsasl2-modules-otp-2.1.22.dfsg1-23ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsasl2-modules-sql", pkgver: "2.1.22.dfsg1-23ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsasl2-modules-sql-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsasl2-modules-sql-2.1.22.dfsg1-23ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "sasl2-bin", pkgver: "2.1.22.dfsg1-23ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package sasl2-bin-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to sasl2-bin-2.1.22.dfsg1-23ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
