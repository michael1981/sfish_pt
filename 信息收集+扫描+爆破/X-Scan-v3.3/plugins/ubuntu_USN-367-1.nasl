# This script was automatically generated from the 367-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27947);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "367-1");
script_summary(english:"Pike vulnerability");
script_name(english:"USN367-1 : Pike vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- pike7.6 
- pike7.6-bzip2 
- pike7.6-core 
- pike7.6-dev 
- pike7.6-doc 
- pike7.6-gdbm 
- pike7.6-gl 
- pike7.6-gtk 
- pike7.6-image 
- pike7.6-manual 
- pike7.6-meta 
- pike7.6-mysql 
- pike7.6-odbc 
- pike7.6-pcre 
- pike7.6-perl 
- pike7.6-pg 
- pike7.6-reference 
- pike7.6-sane 
- pike7.6-sdl 
- pike7.6-svg 
');
script_set_attribute(attribute:'description', value: 'An SQL injection was discovered in Pike\'s PostgreSQL module.  
Applications using a PostgreSQL database and uncommon character 
encodings could be fooled into running arbitrary SQL commands, which 
could result in privilege escalation within the application, application 
data exposure, or denial of service.

Please refer to http://www.ubuntu.com/usn/usn-288-1 for more detailled 
information.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- pike7.6-7.6.13-1ubuntu0.1 (Ubuntu 5.04)
- pike7.6-bzip2-7.6.13-1ubuntu0.1 (Ubuntu 5.04)
- pike7.6-core-7.6.13-1ubuntu0.1 (Ubuntu 5.04)
- pike7.6-dev-7.6.13-1ubuntu0.1 (Ubuntu 5.04)
- pike7.6-doc-7.6.13-1ubuntu0.1 (Ubuntu 5.04)
- pike7.6-gdbm-7.6.13-1ubuntu0.1 (Ubuntu 5.04)
- pike7.6-gl-7.6.13-1ubuntu0.1 (Ubuntu 5.04)
- pike7.6-gtk-7.6.13-1ubuntu0.1 (Ubuntu 5.04)
- pike7.6-image-7.6.13-1ubuntu0.1 (Ubuntu 5.04)
- pike7.6-manual-7.6.13-1ubuntu0.1 (Ubuntu 5.04)
- pike7.6-meta-7.6.13-1ubuntu0.1 
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4041");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "pike7.6", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-bzip2", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-bzip2-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-bzip2-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-core", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-core-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-core-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-dev", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-dev-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-doc", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-doc-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-gdbm", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-gdbm-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-gdbm-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-gl", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-gl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-gl-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-gtk", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-gtk-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-gtk-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-image", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-image-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-image-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-manual", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-manual-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-manual-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-meta", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-meta-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-meta-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-mysql", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-mysql-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-mysql-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-odbc", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-odbc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-odbc-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-pcre", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-pcre-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-pcre-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-perl", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-perl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-perl-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-pg", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-pg-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-pg-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-reference", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-reference-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-reference-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-sane", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-sane-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-sane-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-sdl", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-sdl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-sdl-7.6.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pike7.6-svg", pkgver: "7.6.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pike7.6-svg-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pike7.6-svg-7.6.13-1ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
