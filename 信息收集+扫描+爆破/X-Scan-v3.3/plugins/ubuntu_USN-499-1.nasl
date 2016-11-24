# This script was automatically generated from the 499-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28102);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "499-1");
script_summary(english:"Apache vulnerabilities");
script_name(english:"USN499-1 : Apache vulnerabilities");
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
- apache2-threaded-dev 
- apache2-utils 
- apache2.2-common 
- libapr0 
- libapr0-dev 
');
script_set_attribute(attribute:'description', value: 'Stefan Esser discovered that mod_status did not force a character set,
which could result in browsers becoming vulnerable to XSS attacks when
processing the output.  If a user were tricked into viewing server
status output during a crafted server request, a remote attacker could
exploit this to modify the contents, or steal confidential data (such as
passwords), within the same domain.  By default, mod_status is disabled
in Ubuntu. (CVE-2006-5752)

Niklas Edmundsson discovered that the mod_cache module could be made to
crash using a specially crafted request.  A remote user could use this
to cause a denial of service if Apache was configured to use a threaded
worker.  By default, mod_cache is disabled in Ubuntu. (CVE-2007-1863)

A flaw was discovered in the signal handling of Apache.  A local
attacker could trick Apache into sending SIGUSR1 to other processes.
The vulnerable code was only present in Ubuntu Feisty. (CVE-2007-3304)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- apache2-2.2.3-3.2ubuntu0.1 (Ubuntu 7.04)
- apache2-common-2.0.55-4ubuntu4.1 (Ubuntu 6.10)
- apache2-doc-2.2.3-3.2ubuntu0.1 (Ubuntu 7.04)
- apache2-mpm-event-2.2.3-3.2ubuntu0.1 (Ubuntu 7.04)
- apache2-mpm-perchild-2.2.3-3.2ubuntu0.1 (Ubuntu 7.04)
- apache2-mpm-prefork-2.2.3-3.2ubuntu0.1 (Ubuntu 7.04)
- apache2-mpm-worker-2.2.3-3.2ubuntu0.1 (Ubuntu 7.04)
- apache2-prefork-dev-2.2.3-3.2ubuntu0.1 (Ubuntu 7.04)
- apache2-src-2.2.3-3.2ubuntu0.1 (Ubuntu 7.04)
- apache2-threaded-dev-2.2.3-3.2ubuntu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-5752","CVE-2007-1863","CVE-2007-3304");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "apache2", pkgver: "2.2.3-3.2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to apache2-2.2.3-3.2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "apache2-common", pkgver: "2.0.55-4ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-common-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to apache2-common-2.0.55-4ubuntu4.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "apache2-doc", pkgver: "2.2.3-3.2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-doc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to apache2-doc-2.2.3-3.2ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "apache2-mpm-event", pkgver: "2.2.3-3.2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-event-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to apache2-mpm-event-2.2.3-3.2ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "apache2-mpm-perchild", pkgver: "2.2.3-3.2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-perchild-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to apache2-mpm-perchild-2.2.3-3.2ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "apache2-mpm-prefork", pkgver: "2.2.3-3.2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-prefork-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to apache2-mpm-prefork-2.2.3-3.2ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "apache2-mpm-worker", pkgver: "2.2.3-3.2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-worker-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to apache2-mpm-worker-2.2.3-3.2ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "apache2-prefork-dev", pkgver: "2.2.3-3.2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-prefork-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to apache2-prefork-dev-2.2.3-3.2ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "apache2-src", pkgver: "2.2.3-3.2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-src-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to apache2-src-2.2.3-3.2ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "apache2-threaded-dev", pkgver: "2.2.3-3.2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-threaded-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to apache2-threaded-dev-2.2.3-3.2ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "apache2-utils", pkgver: "2.2.3-3.2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-utils-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to apache2-utils-2.2.3-3.2ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "apache2.2-common", pkgver: "2.2.3-3.2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2.2-common-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to apache2.2-common-2.2.3-3.2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libapr0", pkgver: "2.0.55-4ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr0-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libapr0-2.0.55-4ubuntu4.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libapr0-dev", pkgver: "2.0.55-4ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr0-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libapr0-dev-2.0.55-4ubuntu4.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
