# This script was automatically generated from the 288-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27858);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "288-2");
script_summary(english:"PostgreSQL server/client vulnerabilities");
script_name(english:"USN288-2 : PostgreSQL server/client vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libecpg-compat2 
- libecpg-dev 
- libecpg5 
- libpgtypes2 
- libpq-dev 
- libpq4 
- postgresql-8.1 
- postgresql-client-8.1 
- postgresql-contrib-8.1 
- postgresql-doc-8.1 
- postgresql-plperl-8.1 
- postgresql-plpython-8.1 
- postgresql-pltcl-8.1 
- postgresql-server-dev-8.1 
');
script_set_attribute(attribute:'description', value: 'USN-288-1 fixed two vulnerabilities in Ubuntu 5.04 and Ubuntu 5.10.
This update fixes the same vulnerabilities for Ubuntu 6.06 LTS.

For reference, these are the details of the original USN:

  CVE-2006-2313:
    Akio Ishida and Yasuo Ohgaki discovered a weakness in the handling of
    invalidly-encoded multibyte text data. If a client application
    processed untrusted input without respecting its encoding and applied
    standard string escaping techniques (such as replacing a single quote
    >>\'<< with >>\\\'<< or >>\'\'<<), the PostgreSQL server could interpret the
    resulting string in a way that allowed an attacker to inject arbitrary
    SQL commands into the resulting SQL query. The PostgreSQL server has
    been modified to reject such invalidly encoded strings now, which
    completely fixes the problem for some \'safe\' multibyte encodings like
    UTF-8.
  
  CVE-2006-2314:
    However, there are some less popular and client-only multibyte
    encodings (such as SJIS, BIG5, GBK, GB18030, and
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libecpg-compat2-8.1.4-0ubuntu1 (Ubuntu 6.06)
- libecpg-dev-8.1.4-0ubuntu1 (Ubuntu 6.06)
- libecpg5-8.1.4-0ubuntu1 (Ubuntu 6.06)
- libpgtypes2-8.1.4-0ubuntu1 (Ubuntu 6.06)
- libpq-dev-8.1.4-0ubuntu1 (Ubuntu 6.06)
- libpq4-8.1.4-0ubuntu1 (Ubuntu 6.06)
- postgresql-8.1-8.1.4-0ubuntu1 (Ubuntu 6.06)
- postgresql-client-8.1-8.1.4-0ubuntu1 (Ubuntu 6.06)
- postgresql-contrib-8.1-8.1.4-0ubuntu1 (Ubuntu 6.06)
- postgresql-doc-8.1-8.1.4-0ubuntu1 (Ubuntu 6.06)
- postgresql-plperl-8.1-8.1.4-0ubuntu1 (Ub
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-2313","CVE-2006-2314");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libecpg-compat2", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-compat2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libecpg-compat2-8.1.4-0ubuntu1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libecpg-dev", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libecpg-dev-8.1.4-0ubuntu1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libecpg5", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg5-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libecpg5-8.1.4-0ubuntu1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpgtypes2", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpgtypes2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpgtypes2-8.1.4-0ubuntu1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpq-dev", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpq-dev-8.1.4-0ubuntu1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpq4", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpq4-8.1.4-0ubuntu1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-8.1", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-8.1-8.1.4-0ubuntu1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-client-8.1", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-client-8.1-8.1.4-0ubuntu1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-contrib-8.1", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-contrib-8.1-8.1.4-0ubuntu1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-doc-8.1", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-doc-8.1-8.1.4-0ubuntu1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-plperl-8.1", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-plperl-8.1-8.1.4-0ubuntu1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-plpython-8.1", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-plpython-8.1-8.1.4-0ubuntu1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-pltcl-8.1", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-pltcl-8.1-8.1.4-0ubuntu1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-server-dev-8.1", pkgver: "8.1.4-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-server-dev-8.1-8.1.4-0ubuntu1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
