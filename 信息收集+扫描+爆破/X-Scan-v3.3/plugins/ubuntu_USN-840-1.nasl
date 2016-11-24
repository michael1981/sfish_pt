# This script was automatically generated from the 840-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(41969);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "840-1");
script_summary(english:"openoffice.org vulnerabilities");
script_name(english:"USN840-1 : openoffice.org vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- broffice.org 
- cli-uno-bridge 
- libmythes-dev 
- libuno-cil 
- libuno-cli-basetypes1.0-cil 
- libuno-cli-cppuhelper1.0-cil 
- libuno-cli-oootypes1.0-cil 
- libuno-cli-types1.1-cil 
- libuno-cli-ure1.0-cil 
- libuno-cli-uretypes1.0-cil 
- mozilla-openoffice.org 
- openoffice.org 
- openoffice.org-base 
- openoffice.org-base-core 
- openoffice.org-calc 
- openoffice.org-common 
- openoffice.org-core 
- openoffice.org-dev 
- openoffice.org-dev-doc 
- op
[...]');
script_set_attribute(attribute:'description', value: 'Dyon Balding discovered flaws in the way OpenOffice.org handled tables. If
a user were tricked into opening a specially crafted Word document, a
remote attacker might be able to execute arbitrary code with user
privileges. (CVE-2009-0200, CVE-2009-0201)

A memory overflow flaw was discovered in OpenOffice.org\'s handling of EMF
files. If a user were tricked into opening a specially crafted document, a
remote attacker might be able to execute arbitrary code with user
privileges. (CVE-2009-2139)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- broffice.org-3.0.1-9ubuntu3.1 (Ubuntu 9.04)
- cli-uno-bridge-3.0.1-9ubuntu3.1 (Ubuntu 9.04)
- libmythes-dev-3.0.1-9ubuntu3.1 (Ubuntu 9.04)
- libuno-cil-2.4.1-1ubuntu2.2 (Ubuntu 8.04)
- libuno-cli-basetypes1.0-cil-1.0.12.0+OOo3.0.1-9ubuntu3.1 (Ubuntu 9.04)
- libuno-cli-cppuhelper1.0-cil-1.0.15.0+OOo3.0.1-9ubuntu3.1 (Ubuntu 9.04)
- libuno-cli-oootypes1.0-cil-1.0.1.0+OOo3.0.1-9ubuntu3.1 (Ubuntu 9.04)
- libuno-cli-types1.1-cil-1.1.13.0+OOo2.4.1-11ubuntu2.2 (Ubuntu 8.10)
- libuno-cli-ure1.0-cil-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0200","CVE-2009-0201","CVE-2009-2139");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "broffice.org", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package broffice.org-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to broffice.org-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "cli-uno-bridge", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cli-uno-bridge-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cli-uno-bridge-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmythes-dev", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmythes-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmythes-dev-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libuno-cil", pkgver: "2.4.1-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libuno-cil-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libuno-cil-2.4.1-1ubuntu2.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libuno-cli-basetypes1.0-cil", pkgver: "1.0.12.0+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libuno-cli-basetypes1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libuno-cli-basetypes1.0-cil-1.0.12.0+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libuno-cli-cppuhelper1.0-cil", pkgver: "1.0.15.0+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libuno-cli-cppuhelper1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libuno-cli-cppuhelper1.0-cil-1.0.15.0+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libuno-cli-oootypes1.0-cil", pkgver: "1.0.1.0+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libuno-cli-oootypes1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libuno-cli-oootypes1.0-cil-1.0.1.0+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libuno-cli-types1.1-cil", pkgver: "1.1.13.0+OOo2.4.1-11ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libuno-cli-types1.1-cil-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libuno-cli-types1.1-cil-1.1.13.0+OOo2.4.1-11ubuntu2.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libuno-cli-ure1.0-cil", pkgver: "1.0.15.0+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libuno-cli-ure1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libuno-cli-ure1.0-cil-1.0.15.0+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libuno-cli-uretypes1.0-cil", pkgver: "1.0.1.0+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libuno-cli-uretypes1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libuno-cli-uretypes1.0-cil-1.0.1.0+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mozilla-openoffice.org", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-openoffice.org-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mozilla-openoffice.org-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-base", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-base-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-base-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-base-core", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-base-core-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-base-core-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-calc", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-calc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-calc-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-common", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-common-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-common-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-core", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-core-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-core-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-dev", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-dev-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-dev-doc", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-dev-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-dev-doc-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-draw", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-draw-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-draw-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-dtd-officedocument1.0", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-dtd-officedocument1.0-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-dtd-officedocument1.0-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-emailmerge", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-emailmerge-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-emailmerge-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-evolution", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-evolution-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-evolution-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-filter-binfilter", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-filter-binfilter-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-filter-binfilter-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-filter-mobiledev", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-filter-mobiledev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-filter-mobiledev-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-gcj", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-gcj-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-gcj-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-gnome", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-gnome-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-gnome-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-gtk", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-gtk-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-gtk-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-headless", pkgver: "2.4.1-11ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-headless-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-headless-2.4.1-11ubuntu2.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-impress", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-impress-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-impress-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-java-common", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-java-common-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-java-common-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-kab", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-kab-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-kab-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-kde", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-kde-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-kde-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-l10n-in", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-in-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-l10n-in-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-l10n-za", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-za-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-l10n-za-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-math", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-math-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-math-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-officebean", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-officebean-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-officebean-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-ogltrans", pkgver: "2.4.1-11ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-ogltrans-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-ogltrans-2.4.1-11ubuntu2.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-pdfimport", pkgver: "0.3.2+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-pdfimport-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-pdfimport-0.3.2+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-presentation-minimizer", pkgver: "1.0+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-presentation-minimizer-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-presentation-minimizer-1.0+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-presenter-console", pkgver: "1.0+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-presenter-console-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-presenter-console-1.0+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-qa-api-tests", pkgver: "2.4.1-11ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-qa-api-tests-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-qa-api-tests-2.4.1-11ubuntu2.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-qa-tools", pkgver: "2.4.1-11ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-qa-tools-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-qa-tools-2.4.1-11ubuntu2.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-report-builder", pkgver: "1.0.5+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-report-builder-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-report-builder-1.0.5+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-report-builder-bin", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-report-builder-bin-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-report-builder-bin-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-sdbc-postgresql", pkgver: "0.7.6+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-sdbc-postgresql-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-sdbc-postgresql-0.7.6+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-style-andromeda", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-andromeda-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-style-andromeda-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-style-crystal", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-crystal-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-style-crystal-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-style-galaxy", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-galaxy-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-style-galaxy-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-style-hicontrast", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-hicontrast-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-style-hicontrast-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-style-human", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-human-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-style-human-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-style-industrial", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-industrial-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-style-industrial-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-style-tango", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-tango-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-style-tango-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-wiki-publisher", pkgver: "1.0+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-wiki-publisher-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-wiki-publisher-1.0+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openoffice.org-writer", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-writer-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openoffice.org-writer-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "python-uno", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-uno-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to python-uno-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ttf-opensymbol", pkgver: "3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ttf-opensymbol-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ttf-opensymbol-3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "uno-libs3", pkgver: "1.4.1+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package uno-libs3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to uno-libs3-1.4.1+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "uno-libs3-dbg", pkgver: "1.4.1+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package uno-libs3-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to uno-libs3-dbg-1.4.1+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ure", pkgver: "1.4.1+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ure-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ure-1.4.1+OOo3.0.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ure-dbg", pkgver: "1.4.1+OOo3.0.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ure-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ure-dbg-1.4.1+OOo3.0.1-9ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
