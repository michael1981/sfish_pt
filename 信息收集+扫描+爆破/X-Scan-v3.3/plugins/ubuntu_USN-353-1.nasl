# This script was automatically generated from the 353-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27933);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "353-1");
script_summary(english:"openssl vulnerabilities");
script_name(english:"USN353-1 : openssl vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libssl-dev 
- libssl0.9.7 
- libssl0.9.8 
- libssl0.9.8-dbg 
- openssl 
');
script_set_attribute(attribute:'description', value: 'Dr. Henson of the OpenSSL core team and Open Network Security
discovered a mishandled error condition in the ASN.1 parser. By
sending specially crafted packet data, a remote attacker could exploit
this to trigger an infinite loop, which would render the service
unusable and consume all available system memory. (CVE-2006-2937)

Certain types of public key could take disproportionate amounts of
time to process. The library now limits the maximum key exponent size
to avoid Denial of Service attacks. (CVE-2006-2940)

Tavis Ormandy and Will Drewry of the Google Security Team discovered a
buffer overflow in the SSL_get_shared_ciphers() function. By sending
specially crafted packets to applications that use this function (like
Exim, MySQL, or the openssl command line tool), a remote attacker
could exploit this to execute arbitrary code with the server\'s
privileges. (CVE-2006-3738)

Tavis Ormandy and Will Drewry of the Google Security Team reported
that the get_server_hello() function did not sufficiently check the
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libssl-dev-0.9.8a-7ubuntu0.2 (Ubuntu 6.06)
- libssl0.9.7-0.9.7g-1ubuntu1.3 (Ubuntu 5.10)
- libssl0.9.8-0.9.8a-7ubuntu0.2 (Ubuntu 6.06)
- libssl0.9.8-dbg-0.9.8a-7ubuntu0.2 (Ubuntu 6.06)
- openssl-0.9.8a-7ubuntu0.2 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-2937","CVE-2006-2940","CVE-2006-3738","CVE-2006-4343");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libssl-dev", pkgver: "0.9.8a-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libssl-dev-0.9.8a-7ubuntu0.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libssl0.9.7", pkgver: "0.9.7g-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libssl0.9.7-0.9.7g-1ubuntu1.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libssl0.9.8", pkgver: "0.9.8a-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libssl0.9.8-0.9.8a-7ubuntu0.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libssl0.9.8-dbg", pkgver: "0.9.8a-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.8-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libssl0.9.8-dbg-0.9.8a-7ubuntu0.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openssl", pkgver: "0.9.8a-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssl-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openssl-0.9.8a-7ubuntu0.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
