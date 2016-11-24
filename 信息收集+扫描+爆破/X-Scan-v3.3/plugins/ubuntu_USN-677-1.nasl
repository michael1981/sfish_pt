# This script was automatically generated from the 677-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36611);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "677-1");
script_summary(english:"openoffice.org, openoffice.org-amd64 vulnerabilities");
script_name(english:"USN677-1 : openoffice.org, openoffice.org-amd64 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- broffice.org 
- cli-uno-bridge 
- libmythes-dev 
- libuno-cil 
- libuno-cli-basetypes1.0-cil 
- libuno-cli-cppuhelper1.0-cil 
- libuno-cli-types1.1-cil 
- libuno-cli-ure1.0-cil 
- mozilla-openoffice.org 
- openoffice.org 
- openoffice.org-base 
- openoffice.org-base-core 
- openoffice.org-calc 
- openoffice.org-common 
- openoffice.org-core 
- openoffice.org-dev 
- openoffice.org-dev-doc 
- openoffice.org-draw 
- openoffice.org-dtd-officedocument1.0 
-
[...]');
script_set_attribute(attribute:'description', value: 'Multiple memory overflow flaws were discovered in OpenOffice.org\'s handling of
WMF and EMF files. If a user were tricked into opening a specially crafted
document, a remote attacker might be able to execute arbitrary code with user
privileges. (CVE-2008-2237, CVE-2008-2238)

Dmitry E. Oboukhov discovered that senddoc, as included in OpenOffice.org,
created temporary files in an insecure way. Local users could exploit a race
condition to create or overwrite files with the privileges of the user invoking
the program. This issue only affected Ubuntu 8.04 LTS. (CVE-2008-4937)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- broffice.org-2.4.1-11ubuntu2.1 (Ubuntu 8.10)
- cli-uno-bridge-2.4.1-11ubuntu2.1 (Ubuntu 8.10)
- libmythes-dev-2.4.1-11ubuntu2.1 (Ubuntu 8.10)
- libuno-cil-2.4.1-1ubuntu2.1 (Ubuntu 8.04)
- libuno-cli-basetypes1.0-cil-1.0.10.0+OOo2.4.1-11ubuntu2.1 (Ubuntu 8.10)
- libuno-cli-cppuhelper1.0-cil-1.0.13.0+OOo2.4.1-11ubuntu2.1 (Ubuntu 8.10)
- libuno-cli-types1.1-cil-1.1.13.0+OOo2.4.1-11ubuntu2.1 (Ubuntu 8.10)
- libuno-cli-ure1.0-cil-1.0.13.0+OOo2.4.1-11ubuntu2.1 (Ubuntu 8.10)
- mozilla-openoffice.o
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-2237","CVE-2008-2238","CVE-2008-4937");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "broffice.org", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package broffice.org-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to broffice.org-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "cli-uno-bridge", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cli-uno-bridge-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to cli-uno-bridge-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libmythes-dev", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmythes-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libmythes-dev-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libuno-cil", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libuno-cil-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libuno-cil-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libuno-cli-basetypes1.0-cil", pkgver: "1.0.10.0+OOo2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libuno-cli-basetypes1.0-cil-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libuno-cli-basetypes1.0-cil-1.0.10.0+OOo2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libuno-cli-cppuhelper1.0-cil", pkgver: "1.0.13.0+OOo2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libuno-cli-cppuhelper1.0-cil-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libuno-cli-cppuhelper1.0-cil-1.0.13.0+OOo2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libuno-cli-types1.1-cil", pkgver: "1.1.13.0+OOo2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libuno-cli-types1.1-cil-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libuno-cli-types1.1-cil-1.1.13.0+OOo2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libuno-cli-ure1.0-cil", pkgver: "1.0.13.0+OOo2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libuno-cli-ure1.0-cil-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libuno-cli-ure1.0-cil-1.0.13.0+OOo2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "mozilla-openoffice.org", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-openoffice.org-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to mozilla-openoffice.org-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-base", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-base-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-base-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-base-core", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-base-core-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-base-core-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-calc", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-calc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-calc-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-common", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-common-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-common-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-core", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-core-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-core-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-dev", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-dev-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-dev-doc", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-dev-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-dev-doc-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-draw", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-draw-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-draw-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-dtd-officedocument1.0", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-dtd-officedocument1.0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-dtd-officedocument1.0-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-emailmerge", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-emailmerge-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-emailmerge-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-evolution", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-evolution-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-evolution-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-filter-binfilter", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-filter-binfilter-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-filter-binfilter-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-filter-mobiledev", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-filter-mobiledev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-filter-mobiledev-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-filter-so52", pkgver: "2.0.2-2ubuntu12.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-filter-so52-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-filter-so52-2.0.2-2ubuntu12.7
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-gcj", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-gcj-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-gcj-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-gnome", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-gnome-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-gnome-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-gtk", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-gtk-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-gtk-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-gtk-gnome", pkgver: "2.0.2-2ubuntu12.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-gtk-gnome-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-gtk-gnome-2.0.2-2ubuntu12.7
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-headless", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-headless-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-headless-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-impress", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-impress-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-impress-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-java-common", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-java-common-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-java-common-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-kde", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-kde-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-kde-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "openoffice.org-l10n-en-us", pkgver: "2.3.0-1ubuntu5.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-en-us-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to openoffice.org-l10n-en-us-2.3.0-1ubuntu5.5
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-l10n-in", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-in-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-l10n-in-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-l10n-za", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-za-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-l10n-za-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-math", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-math-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-math-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-officebean", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-officebean-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-officebean-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-ogltrans", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-ogltrans-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-ogltrans-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-presentation-minimizer", pkgver: "1.0+OOo2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-presentation-minimizer-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-presentation-minimizer-1.0+OOo2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-qa-api-tests", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-qa-api-tests-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-qa-api-tests-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-qa-tools", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-qa-tools-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-qa-tools-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-report-builder", pkgver: "1.0.2+OOo2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-report-builder-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-report-builder-1.0.2+OOo2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-report-builder-bin", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-report-builder-bin-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-report-builder-bin-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-sdbc-postgresql", pkgver: "0.7.5+OOo2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-sdbc-postgresql-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-sdbc-postgresql-0.7.5+OOo2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-style-andromeda", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-andromeda-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-style-andromeda-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-style-crystal", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-crystal-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-style-crystal-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "openoffice.org-style-default", pkgver: "2.3.0-1ubuntu5.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-default-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to openoffice.org-style-default-2.3.0-1ubuntu5.5
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-style-hicontrast", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-hicontrast-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-style-hicontrast-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-style-human", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-human-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-style-human-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-style-industrial", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-industrial-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-style-industrial-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-style-tango", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-style-tango-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-style-tango-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openoffice.org-writer", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-writer-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openoffice.org-writer-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2", pkgver: "2.0.2-2ubuntu12.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-2.0.2-2ubuntu12.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-base", pkgver: "2.0.2-2ubuntu12.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-base-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-base-2.0.2-2ubuntu12.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-calc", pkgver: "2.0.2-2ubuntu12.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-calc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-calc-2.0.2-2ubuntu12.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-draw", pkgver: "2.0.2-2ubuntu12.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-draw-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-draw-2.0.2-2ubuntu12.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-evolution", pkgver: "2.0.2-2ubuntu12.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-evolution-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-evolution-2.0.2-2ubuntu12.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-gnome", pkgver: "2.0.2-2ubuntu12.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-gnome-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-gnome-2.0.2-2ubuntu12.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-impress", pkgver: "2.0.2-2ubuntu12.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-impress-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-impress-2.0.2-2ubuntu12.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-kde", pkgver: "2.0.2-2ubuntu12.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-kde-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-kde-2.0.2-2ubuntu12.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-math", pkgver: "2.0.2-2ubuntu12.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-math-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-math-2.0.2-2ubuntu12.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-writer", pkgver: "2.0.2-2ubuntu12.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-writer-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-writer-2.0.2-2ubuntu12.7
');
}
found = ubuntu_check(osver: "8.10", pkgname: "python-uno", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-uno-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to python-uno-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ttf-opensymbol", pkgver: "2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ttf-opensymbol-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ttf-opensymbol-2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ure", pkgver: "1.4+OOo2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ure-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ure-1.4+OOo2.4.1-11ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ure-dbg", pkgver: "1.4+OOo2.4.1-11ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ure-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ure-dbg-1.4+OOo2.4.1-11ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
