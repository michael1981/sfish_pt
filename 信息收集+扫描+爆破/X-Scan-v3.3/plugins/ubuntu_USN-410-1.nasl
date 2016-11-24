# This script was automatically generated from the 410-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27998);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "410-1");
script_summary(english:"poppler vulnerability");
script_name(english:"USN410-1 : poppler vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- kamera 
- karbon 
- kchart 
- kcoloredit 
- kdegraphics 
- kdegraphics-dev 
- kdegraphics-doc-html 
- kdegraphics-kfile-plugins 
- kdvi 
- kexi 
- kfax 
- kformula 
- kgamma 
- kghostview 
- kiconedit 
- kivio 
- kivio-data 
- kmrml 
- koffice 
- koffice-data 
- koffice-dbg 
- koffice-dev 
- koffice-doc 
- koffice-doc-html 
- koffice-libs 
- kolourpaint 
- kooka 
- koshell 
- kpdf 
- kplato 
- kpovmodeler 
- kpresenter 
- kpresenter-data 
- krita 
- kr
[...]');
script_set_attribute(attribute:'description', value: 'The poppler PDF loader library did not limit the recursion depth of
the page model tree. By tricking a user into opening a specially
crafter PDF file, this could be exploited to trigger an infinite loop
and eventually crash an application that uses this library.

kpdf in Ubuntu 5.10, and KOffice in all Ubuntu releases contains a
copy of this code and thus is affected as well.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- kamera-3.4.3-0ubuntu2.6 (Ubuntu 5.10)
- karbon-1.5.2-0ubuntu2.1 (Ubuntu 6.10)
- kchart-1.5.2-0ubuntu2.1 (Ubuntu 6.10)
- kcoloredit-3.4.3-0ubuntu2.6 (Ubuntu 5.10)
- kdegraphics-3.4.3-0ubuntu2.6 (Ubuntu 5.10)
- kdegraphics-dev-3.4.3-0ubuntu2.6 (Ubuntu 5.10)
- kdegraphics-doc-html-3.4.3-0ubuntu2.6 (Ubuntu 5.10)
- kdegraphics-kfile-plugins-3.4.3-0ubuntu2.6 (Ubuntu 5.10)
- kdvi-3.4.3-0ubuntu2.6 (Ubuntu 5.10)
- kexi-1.5.2-0ubuntu2.1 (Ubuntu 6.10)
- kfax-3.4.3-0ubuntu2.6 (Ubuntu 5.10)
- kformula-1
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-0104");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "kamera", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kamera-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kamera-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "karbon", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package karbon-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to karbon-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kchart", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kchart-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kchart-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kcoloredit", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kcoloredit-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kcoloredit-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdegraphics", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdegraphics-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdegraphics-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdegraphics-dev", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdegraphics-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdegraphics-dev-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdegraphics-doc-html", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdegraphics-doc-html-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdegraphics-doc-html-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdegraphics-kfile-plugins", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdegraphics-kfile-plugins-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdegraphics-kfile-plugins-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdvi", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdvi-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdvi-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kexi", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kexi-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kexi-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kfax", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kfax-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kfax-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kformula", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kformula-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kformula-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kgamma", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kgamma-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kgamma-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kghostview", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kghostview-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kghostview-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kiconedit", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kiconedit-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kiconedit-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kivio", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kivio-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kivio-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kivio-data", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kivio-data-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kivio-data-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kmrml", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kmrml-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kmrml-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "koffice", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to koffice-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "koffice-data", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-data-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to koffice-data-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "koffice-dbg", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-dbg-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to koffice-dbg-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "koffice-dev", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to koffice-dev-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "koffice-doc", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-doc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to koffice-doc-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "koffice-doc-html", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-doc-html-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to koffice-doc-html-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "koffice-libs", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-libs-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to koffice-libs-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kolourpaint", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kolourpaint-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kolourpaint-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kooka", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kooka-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kooka-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "koshell", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koshell-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to koshell-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kpdf", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kpdf-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kpdf-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kplato", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kplato-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kplato-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kpovmodeler", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kpovmodeler-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kpovmodeler-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kpresenter", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kpresenter-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kpresenter-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kpresenter-data", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kpresenter-data-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kpresenter-data-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "krita", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krita-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to krita-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "krita-data", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krita-data-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to krita-data-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kruler", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kruler-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kruler-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "ksnapshot", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ksnapshot-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to ksnapshot-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kspread", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kspread-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kspread-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "ksvg", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ksvg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to ksvg-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kthesaurus", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kthesaurus-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kthesaurus-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kugar", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kugar-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kugar-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kuickshow", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kuickshow-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kuickshow-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kview", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kview-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kview-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kviewshell", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kviewshell-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kviewshell-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kword", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kword-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kword-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kword-data", pkgver: "1.5.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kword-data-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kword-data-1.5.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libkscan-dev", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkscan-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkscan-dev-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libkscan1", pkgver: "3.4.3-0ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkscan1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkscan1-3.4.3-0ubuntu2.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpoppler-dev", pkgver: "0.5.4-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpoppler-dev-0.5.4-0ubuntu4.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpoppler-glib-dev", pkgver: "0.5.4-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-glib-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpoppler-glib-dev-0.5.4-0ubuntu4.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpoppler-qt-dev", pkgver: "0.5.4-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-qt-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpoppler-qt-dev-0.5.4-0ubuntu4.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpoppler-qt4-dev", pkgver: "0.5.4-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-qt4-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpoppler-qt4-dev-0.5.4-0ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler0c2", pkgver: "0.4.2-0ubuntu6.8");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler0c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler0c2-0.4.2-0ubuntu6.8
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler0c2-glib", pkgver: "0.4.2-0ubuntu6.8");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler0c2-glib-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler0c2-glib-0.4.2-0ubuntu6.8
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler0c2-qt", pkgver: "0.4.2-0ubuntu6.8");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler0c2-qt-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler0c2-qt-0.4.2-0ubuntu6.8
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpoppler1", pkgver: "0.5.4-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpoppler1-0.5.4-0ubuntu4.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpoppler1-glib", pkgver: "0.5.4-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler1-glib-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpoppler1-glib-0.5.4-0ubuntu4.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpoppler1-qt", pkgver: "0.5.4-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler1-qt-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpoppler1-qt-0.5.4-0ubuntu4.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpoppler1-qt4", pkgver: "0.5.4-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler1-qt4-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpoppler1-qt4-0.5.4-0ubuntu4.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "poppler-utils", pkgver: "0.5.4-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package poppler-utils-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to poppler-utils-0.5.4-0ubuntu4.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
