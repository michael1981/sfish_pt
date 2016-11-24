# This script was automatically generated from the 787-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39371);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "787-1");
script_summary(english:"apache2 vulnerabilities");
script_name(english:"USN787-1 : apache2 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- apache2 
- apache2-common 
- apache2-doc 
- apache2-mpm-event 
- apache2-mpm-perchild 
- apache2-mpm-prefork 
- apache2-mpm-worker 
- apache2-prefork-dev 
- apache2-src 
- apache2-suexec 
- apache2-suexec-custom 
- apache2-threaded-dev 
- apache2-utils 
- apache2.2-common 
- libapr0 
- libapr0-dev 
');
script_set_attribute(attribute:'description', value: 'Matthew Palmer discovered an underflow flaw in apr-util as included in
Apache. An attacker could cause a denial of service via application crash
in Apache using a crafted SVNMasterURI directive, .htaccess file, or when
using mod_apreq2. This issue only affected Ubuntu 6.06 LTS. (CVE-2009-0023)

Sander de Boer discovered that mod_proxy_ajp would reuse connections when
a client closed a connection without sending a request body. A remote
attacker could exploit this to obtain sensitive response data. This issue
only affected Ubuntu 9.04. (CVE-2009-1191)

Jonathan Peatfield discovered that Apache did not process Includes options
correctly. With certain configurations of Options and AllowOverride, a
local attacker could use an .htaccess file to override intended
restrictions and execute arbitrary code via a Server-Side-Include file.
This issue affected Ubuntu 8.04 LTS, 8.10 and 9.04. (CVE-2009-1195)

It was discovered that the XML parser did not properly handle entity
expansion. A remote attacker could cause a de
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- apache2-2.2.11-2ubuntu2.1 (Ubuntu 9.04)
- apache2-common-2.0.55-4ubuntu2.5 (Ubuntu 6.06)
- apache2-doc-2.2.11-2ubuntu2.1 (Ubuntu 9.04)
- apache2-mpm-event-2.2.11-2ubuntu2.1 (Ubuntu 9.04)
- apache2-mpm-perchild-2.2.8-1ubuntu0.8 (Ubuntu 8.04)
- apache2-mpm-prefork-2.2.11-2ubuntu2.1 (Ubuntu 9.04)
- apache2-mpm-worker-2.2.11-2ubuntu2.1 (Ubuntu 9.04)
- apache2-prefork-dev-2.2.11-2ubuntu2.1 (Ubuntu 9.04)
- apache2-src-2.2.11-2ubuntu2.1 (Ubuntu 9.04)
- apache2-suexec-2.2.11-2ubuntu2.1 (Ubuntu 9.04
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2009-0023","CVE-2009-1191","CVE-2009-1195","CVE-2009-1955","CVE-2009-1956");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "apache2", pkgver: "2.2.11-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apache2-2.2.11-2ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-common", pkgver: "2.0.55-4ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-common-2.0.55-4ubuntu2.5
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apache2-doc", pkgver: "2.2.11-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apache2-doc-2.2.11-2ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apache2-mpm-event", pkgver: "2.2.11-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-event-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apache2-mpm-event-2.2.11-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "apache2-mpm-perchild", pkgver: "2.2.8-1ubuntu0.8");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-perchild-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to apache2-mpm-perchild-2.2.8-1ubuntu0.8
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apache2-mpm-prefork", pkgver: "2.2.11-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-prefork-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apache2-mpm-prefork-2.2.11-2ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apache2-mpm-worker", pkgver: "2.2.11-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-worker-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apache2-mpm-worker-2.2.11-2ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apache2-prefork-dev", pkgver: "2.2.11-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-prefork-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apache2-prefork-dev-2.2.11-2ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apache2-src", pkgver: "2.2.11-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-src-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apache2-src-2.2.11-2ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apache2-suexec", pkgver: "2.2.11-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-suexec-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apache2-suexec-2.2.11-2ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apache2-suexec-custom", pkgver: "2.2.11-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-suexec-custom-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apache2-suexec-custom-2.2.11-2ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apache2-threaded-dev", pkgver: "2.2.11-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-threaded-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apache2-threaded-dev-2.2.11-2ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apache2-utils", pkgver: "2.2.11-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-utils-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apache2-utils-2.2.11-2ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apache2.2-common", pkgver: "2.2.11-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2.2-common-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apache2.2-common-2.2.11-2ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libapr0", pkgver: "2.0.55-4ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libapr0-2.0.55-4ubuntu2.5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libapr0-dev", pkgver: "2.0.55-4ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr0-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libapr0-dev-2.0.55-4ubuntu2.5
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
