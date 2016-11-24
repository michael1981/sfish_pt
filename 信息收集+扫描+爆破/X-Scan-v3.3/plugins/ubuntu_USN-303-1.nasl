# This script was automatically generated from the 303-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27878);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "303-1");
script_summary(english:"MySQL vulnerability");
script_name(english:"USN303-1 : MySQL vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmysqlclient14 
- libmysqlclient14-dev 
- libmysqlclient15-dev 
- libmysqlclient15off 
- mysql-client 
- mysql-client-4.1 
- mysql-client-5.0 
- mysql-common 
- mysql-common-4.1 
- mysql-server 
- mysql-server-4.1 
- mysql-server-5.0 
');
script_set_attribute(attribute:'description', value: 'An SQL injection vulnerability has been discovered when using less
popular multibyte encodings (such as SJIS, or BIG5) which contain
valid multibyte characters that end with the byte 0x5c (the
representation of the backslash character >>\\<< in ASCII). 

Many client libraries and applications use the non-standard, but
popular way of escaping the >>\'<< character by replacing all
occurences of it with >>\\\'<<. If a client application uses one of the
affected encodings and does not interpret multibyte characters, and an
attacker supplies a specially crafted byte sequence as an input string
parameter, this escaping method would then produce a validly-encoded
character and an excess >>\'<< character which would end the string.
All subsequent characters would then be interpreted as SQL code, so
the attacker could execute arbitrary SQL commands.

The updated packages fix the mysql_real_escape_string() function to
escape quote characters in a safe way. If you use third-party software
which uses an ad-hoc method of
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmysqlclient14-4.1.12-1ubuntu3.5 (Ubuntu 5.10)
- libmysqlclient14-dev-4.1.12-1ubuntu3.5 (Ubuntu 5.10)
- libmysqlclient15-dev-5.0.22-0ubuntu6.06 (Ubuntu 6.06)
- libmysqlclient15off-5.0.22-0ubuntu6.06 (Ubuntu 6.06)
- mysql-client-5.0.22-0ubuntu6.06 (Ubuntu 6.06)
- mysql-client-4.1-4.1.12-1ubuntu3.5 (Ubuntu 5.10)
- mysql-client-5.0-5.0.22-0ubuntu6.06 (Ubuntu 6.06)
- mysql-common-5.0.22-0ubuntu6.06 (Ubuntu 6.06)
- mysql-common-4.1-4.1.12-1ubuntu3.5 (Ubuntu 5.10)
- mysql-server-5.0.22-0ubuntu6
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-2753");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libmysqlclient14", pkgver: "4.1.12-1ubuntu3.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient14-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmysqlclient14-4.1.12-1ubuntu3.5
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmysqlclient14-dev", pkgver: "4.1.12-1ubuntu3.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient14-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmysqlclient14-dev-4.1.12-1ubuntu3.5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmysqlclient15-dev", pkgver: "5.0.22-0ubuntu6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmysqlclient15-dev-5.0.22-0ubuntu6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmysqlclient15off", pkgver: "5.0.22-0ubuntu6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15off-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmysqlclient15off-5.0.22-0ubuntu6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-client", pkgver: "5.0.22-0ubuntu6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-client-5.0.22-0ubuntu6.06
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-client-4.1", pkgver: "4.1.12-1ubuntu3.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-4.1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-client-4.1-4.1.12-1ubuntu3.5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-client-5.0", pkgver: "5.0.22-0ubuntu6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-5.0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-client-5.0-5.0.22-0ubuntu6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-common", pkgver: "5.0.22-0ubuntu6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-common-5.0.22-0ubuntu6.06
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-common-4.1", pkgver: "4.1.12-1ubuntu3.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-common-4.1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-common-4.1-4.1.12-1ubuntu3.5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-server", pkgver: "5.0.22-0ubuntu6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-server-5.0.22-0ubuntu6.06
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-server-4.1", pkgver: "4.1.12-1ubuntu3.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-4.1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-server-4.1-4.1.12-1ubuntu3.5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-server-5.0", pkgver: "5.0.22-0ubuntu6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-5.0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-server-5.0-5.0.22-0ubuntu6.06
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
