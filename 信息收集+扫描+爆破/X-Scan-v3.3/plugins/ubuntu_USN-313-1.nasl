# This script was automatically generated from the 313-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27888);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "313-1");
script_summary(english:"openoffice.org-amd64, openoffice.org vulnerabilities");
script_name(english:"USN313-1 : openoffice.org-amd64, openoffice.org vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmythes-dev 
- openoffice.org 
- openoffice.org-base 
- openoffice.org-bin 
- openoffice.org-calc 
- openoffice.org-common 
- openoffice.org-core 
- openoffice.org-dev 
- openoffice.org-dev-doc 
- openoffice.org-draw 
- openoffice.org-evolution 
- openoffice.org-filter-so52 
- openoffice.org-gcj 
- openoffice.org-gnome 
- openoffice.org-gnomevfs 
- openoffice.org-gtk 
- openoffice.org-gtk-gnome 
- openoffice.org-impress 
- openoffice.org-java-common 
[...]');
script_set_attribute(attribute:'description', value: 'It was possible to embed Basic macros in documents in a way that
OpenOffice.org would not ask for confirmation about executing them. By
tricking a user into opening a malicious document, this could be
exploited to run arbitrary Basic code (including local file access and
modification) with the user\'s privileges. (CVE-2006-2198)

A flaw was discovered in the Java sandbox which allowed Java applets
to break out of the sandbox and execute code without restrictions.  By
tricking a user into opening a malicious document, this could be
exploited to run arbitrary code with the user\'s privileges. This
update disables Java applets for OpenOffice.org, since it is not
generally possible to guarantee the sandbox restrictions.
(CVE-2006-2199)

A buffer overflow has been found in the XML parser. By tricking a user
into opening a specially crafted XML file with OpenOffice.org, this
could be exploited to execute arbitrary code with the user\'s
privileges. (CVE-2006-3117)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmythes-dev-2.0.2-2ubuntu12.1 (Ubuntu 6.06)
- openoffice.org-2.0.2-2ubuntu12.1 (Ubuntu 6.06)
- openoffice.org-base-2.0.2-2ubuntu12.1 (Ubuntu 6.06)
- openoffice.org-bin-1.1.3-8ubuntu2.4 (Ubuntu 5.04)
- openoffice.org-calc-2.0.2-2ubuntu12.1 (Ubuntu 6.06)
- openoffice.org-common-2.0.2-2ubuntu12.1 (Ubuntu 6.06)
- openoffice.org-core-2.0.2-2ubuntu12.1 (Ubuntu 6.06)
- openoffice.org-dev-2.0.2-2ubuntu12.1 (Ubuntu 6.06)
- openoffice.org-dev-doc-2.0.2-2ubuntu12.1 (Ubuntu 6.06)
- openoffice.org-dra
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-2198","CVE-2006-2199","CVE-2006-3117");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libmythes-dev", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmythes-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmythes-dev-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-base", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-base-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-base-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-bin", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-bin-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-bin-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-calc", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-calc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-calc-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-common", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-common-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-core", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-core-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-core-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-dev", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-dev-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-dev-doc", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-dev-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-dev-doc-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-draw", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-draw-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-draw-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-evolution", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-evolution-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-evolution-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-filter-so52", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-filter-so52-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-filter-so52-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-gcj", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-gcj-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-gcj-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-gnome", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-gnome-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-gnome-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-gnomevfs", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-gnomevfs-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-gnomevfs-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-gtk", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-gtk-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-gtk-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-gtk-gnome", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-gtk-gnome-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-gtk-gnome-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-impress", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-impress-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-impress-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-java-common", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-java-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-java-common-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-kde", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-kde-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-kde-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-af", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-af-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-af-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-ar", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ar-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-ar-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-ca", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ca-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-ca-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-cs", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-cs-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-cs-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-cy", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-cy-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-cy-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-da", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-da-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-da-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-de", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-de-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-de-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-el", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-el-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-el-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-en", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-en-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-en-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-l10n-en-us", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-en-us-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-l10n-en-us-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-es", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-es-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-es-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-et", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-et-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-et-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-eu", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-eu-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-eu-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-fi", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-fi-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-fi-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-fr", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-fr-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-fr-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-gl", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-gl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-gl-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-he", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-he-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-he-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-hi", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-hi-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-hi-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-hu", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-hu-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-hu-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-it", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-it-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-it-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-ja", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ja-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-ja-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-kn", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-kn-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-kn-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-ko", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ko-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-ko-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-lt", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-lt-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-lt-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-nb", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-nb-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-nb-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-nl", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-nl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-nl-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-nn", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-nn-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-nn-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-ns", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ns-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-ns-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-pl", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-pl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-pl-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-pt", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-pt-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-pt-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-pt-br", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-pt-br-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-pt-br-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-ru", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ru-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-ru-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-sk", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-sk-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-sk-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-sl", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-sl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-sl-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-sv", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-sv-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-sv-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-th", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-th-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-th-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-tn", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-tn-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-tn-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-tr", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-tr-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-tr-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-xh", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-xh-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-xh-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-zh-cn", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-zh-cn-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-zh-cn-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-zh-tw", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-zh-tw-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-zh-tw-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-zu", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-zu-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-zu-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-math", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-math-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-math-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-mimelnk", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-mimelnk-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-mimelnk-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-officebean", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-officebean-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-officebean-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-qa-api-tests", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-qa-api-tests-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-qa-api-tests-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-qa-tools", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-qa-tools-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-qa-tools-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-thesaurus-en-us", pkgver: "1.1.3-8ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-thesaurus-en-us-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-thesaurus-en-us-1.1.3-8ubuntu2.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org-writer", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-writer-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org-writer-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-base", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-base-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-base-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-calc", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-calc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-calc-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-draw", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-draw-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-draw-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-evolution", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-evolution-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-evolution-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-gnome", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-gnome-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-gnome-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-impress", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-impress-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-impress-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-kde", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-kde-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-kde-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-math", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-math-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-math-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openoffice.org2-writer", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-writer-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openoffice.org2-writer-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python-uno", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-uno-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python-uno-2.0.2-2ubuntu12.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ttf-opensymbol", pkgver: "2.0.2-2ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ttf-opensymbol-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ttf-opensymbol-2.0.2-2ubuntu12.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
