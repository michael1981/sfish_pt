# This script was automatically generated from the 133-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20524);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "133-1");
script_summary(english:"apache vulnerability");
script_name(english:"USN133-1 : apache vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- apache 
- apache-common 
- apache-dbg 
- apache-dev 
- apache-doc 
- apache-perl 
- apache-ssl 
- apache-utils 
- libapache-mod-perl 
');
script_set_attribute(attribute:'description', value: 'A buffer overflow was discovered in the "htpasswd" utility. This could
be exploited to execute arbitrary code with the privileges of the user
invoking htpasswd. This is only a security vulnerability if you have a
website that offers a public interface to htpasswd without checking
the input beforehand; however, this is very unusual.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- apache-1.3.31-6ubuntu0.7 (Ubuntu 4.10)
- apache-common-1.3.31-6ubuntu0.7 (Ubuntu 4.10)
- apache-dbg-1.3.31-6ubuntu0.7 (Ubuntu 4.10)
- apache-dev-1.3.31-6ubuntu0.7 (Ubuntu 4.10)
- apache-doc-1.3.31-6ubuntu0.7 (Ubuntu 4.10)
- apache-perl-1.3.31-6ubuntu0.7 (Ubuntu 4.10)
- apache-ssl-1.3.31-6ubuntu0.7 (Ubuntu 4.10)
- apache-utils-1.3.31-6ubuntu0.7 (Ubuntu 4.10)
- libapache-mod-perl-1.29.0.2.0-6ubuntu0.7 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "apache", pkgver: "1.3.31-6ubuntu0.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-1.3.31-6ubuntu0.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-common", pkgver: "1.3.31-6ubuntu0.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-common-1.3.31-6ubuntu0.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-dbg", pkgver: "1.3.31-6ubuntu0.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-dbg-1.3.31-6ubuntu0.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-dev", pkgver: "1.3.31-6ubuntu0.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-dev-1.3.31-6ubuntu0.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-doc", pkgver: "1.3.31-6ubuntu0.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-doc-1.3.31-6ubuntu0.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-perl", pkgver: "1.3.31-6ubuntu0.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-perl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-perl-1.3.31-6ubuntu0.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-ssl", pkgver: "1.3.31-6ubuntu0.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-ssl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-ssl-1.3.31-6ubuntu0.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-utils", pkgver: "1.3.31-6ubuntu0.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-utils-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-utils-1.3.31-6ubuntu0.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libapache-mod-perl", pkgver: "1.29.0.2.0-6ubuntu0.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache-mod-perl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libapache-mod-perl-1.29.0.2.0-6ubuntu0.7
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
