# This script was automatically generated from the 860-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42858);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "860-1");
script_summary(english:"apache2 vulnerabilities");
script_name(english:"USN860-1 : apache2 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- apache2 
- apache2-common 
- apache2-doc 
- apache2-mpm-event 
- apache2-mpm-itk 
- apache2-mpm-perchild 
- apache2-mpm-prefork 
- apache2-mpm-worker 
- apache2-prefork-dev 
- apache2-src 
- apache2-suexec 
- apache2-suexec-custom 
- apache2-threaded-dev 
- apache2-utils 
- apache2.2-bin 
- apache2.2-common 
- libapr0 
- libapr0-dev 
');
script_set_attribute(attribute:'description', value: 'Marsh Ray and Steve Dispensa discovered a flaw in the TLS and SSLv3
protocols. If an attacker could perform a man in the middle attack at the
start of a TLS connection, the attacker could inject arbitrary content at
the beginning of the user\'s session. The flaw is with TLS renegotiation and
potentially affects any software that supports this feature. Attacks
against the HTTPS protocol are known, with the severity of the issue
depending on the safeguards used in the web application. Until the TLS
protocol and underlying libraries are adjusted to defend against this
vulnerability, a partial, temporary workaround has been applied to Apache
that disables client initiated TLS renegotiation. This update does not
protect against server initiated TLS renegotiation when using
SSLVerifyClient and SSLCipherSuite on a per Directory or Location basis.
Users can defend againt server inititiated TLS renegotiation attacks by
adjusting their Apache configuration to use SSLVerifyClient and
SSLCipherSuite only on the server o
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- apache2-2.2.12-1ubuntu2.1 (Ubuntu 9.10)
- apache2-common-2.0.55-4ubuntu2.9 (Ubuntu 6.06)
- apache2-doc-2.2.12-1ubuntu2.1 (Ubuntu 9.10)
- apache2-mpm-event-2.2.12-1ubuntu2.1 (Ubuntu 9.10)
- apache2-mpm-itk-2.2.12-1ubuntu2.1 (Ubuntu 9.10)
- apache2-mpm-perchild-2.2.8-1ubuntu0.14 (Ubuntu 8.04)
- apache2-mpm-prefork-2.2.12-1ubuntu2.1 (Ubuntu 9.10)
- apache2-mpm-worker-2.2.12-1ubuntu2.1 (Ubuntu 9.10)
- apache2-prefork-dev-2.2.12-1ubuntu2.1 (Ubuntu 9.10)
- apache2-src-2.2.11-2ubuntu2.5 (Ubuntu 9.
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-3094","CVE-2009-3095","CVE-2009-3555");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.10", pkgname: "apache2", pkgver: "2.2.12-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to apache2-2.2.12-1ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-common", pkgver: "2.0.55-4ubuntu2.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-common-2.0.55-4ubuntu2.9
');
}
found = ubuntu_check(osver: "9.10", pkgname: "apache2-doc", pkgver: "2.2.12-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-doc-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to apache2-doc-2.2.12-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "apache2-mpm-event", pkgver: "2.2.12-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-event-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to apache2-mpm-event-2.2.12-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "apache2-mpm-itk", pkgver: "2.2.12-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-itk-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to apache2-mpm-itk-2.2.12-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "apache2-mpm-perchild", pkgver: "2.2.8-1ubuntu0.14");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-perchild-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to apache2-mpm-perchild-2.2.8-1ubuntu0.14
');
}
found = ubuntu_check(osver: "9.10", pkgname: "apache2-mpm-prefork", pkgver: "2.2.12-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-prefork-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to apache2-mpm-prefork-2.2.12-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "apache2-mpm-worker", pkgver: "2.2.12-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-worker-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to apache2-mpm-worker-2.2.12-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "apache2-prefork-dev", pkgver: "2.2.12-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-prefork-dev-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to apache2-prefork-dev-2.2.12-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apache2-src", pkgver: "2.2.11-2ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-src-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apache2-src-2.2.11-2ubuntu2.5
');
}
found = ubuntu_check(osver: "9.10", pkgname: "apache2-suexec", pkgver: "2.2.12-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-suexec-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to apache2-suexec-2.2.12-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "apache2-suexec-custom", pkgver: "2.2.12-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-suexec-custom-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to apache2-suexec-custom-2.2.12-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "apache2-threaded-dev", pkgver: "2.2.12-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-threaded-dev-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to apache2-threaded-dev-2.2.12-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "apache2-utils", pkgver: "2.2.12-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-utils-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to apache2-utils-2.2.12-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "apache2.2-bin", pkgver: "2.2.12-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2.2-bin-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to apache2.2-bin-2.2.12-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "apache2.2-common", pkgver: "2.2.12-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2.2-common-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to apache2.2-common-2.2.12-1ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libapr0", pkgver: "2.0.55-4ubuntu2.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libapr0-2.0.55-4ubuntu2.9
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libapr0-dev", pkgver: "2.0.55-4ubuntu2.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr0-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libapr0-dev-2.0.55-4ubuntu2.9
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
