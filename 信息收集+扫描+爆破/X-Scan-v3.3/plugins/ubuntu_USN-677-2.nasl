# This script was automatically generated from the 677-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37546);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "677-2");
script_summary(english:"openoffice.org-l10n update");
script_name(english:"USN677-2 : openoffice.org-l10n update");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- openoffice.org-help-br 
- openoffice.org-help-cs 
- openoffice.org-help-da 
- openoffice.org-help-de 
- openoffice.org-help-dz 
- openoffice.org-help-en-gb 
- openoffice.org-help-en-us 
- openoffice.org-help-es 
- openoffice.org-help-et 
- openoffice.org-help-eu 
- openoffice.org-help-fr 
- openoffice.org-help-gl 
- openoffice.org-help-hi-in 
- openoffice.org-help-hu 
- openoffice.org-help-it 
- openoffice.org-help-ja 
- openoffice.org-help-km 
- openo
[...]');
script_set_attribute(attribute:'description', value: 'USN-677-1 fixed vulnerabilities in OpenOffice.org. The changes required that
openoffice.org-l10n also be updated for the new version in Ubuntu 8.04 LTS.

Original advisory details:

 Multiple memory overflow flaws were discovered in OpenOffice.org\'s handling of
 WMF and EMF files. If a user were tricked into opening a specially crafted
 document, a remote attacker might be able to execute arbitrary code with user
 privileges. (CVE-2008-2237, CVE-2008-2238)
 
 Dmitry E. Oboukhov discovered that senddoc, as included in OpenOffice.org,
 created temporary files in an insecure way. Local users could exploit a race
 condition to create or overwrite files with the privileges of the user invoking
 the program. This issue only affected Ubuntu 8.04 LTS. (CVE-2008-4937)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- openoffice.org-help-br-2.4.1-1ubuntu2.1 (Ubuntu 8.04)
- openoffice.org-help-cs-2.4.1-1ubuntu2.1 (Ubuntu 8.04)
- openoffice.org-help-da-2.4.1-1ubuntu2.1 (Ubuntu 8.04)
- openoffice.org-help-de-2.4.1-1ubuntu2.1 (Ubuntu 8.04)
- openoffice.org-help-dz-2.4.1-1ubuntu2.1 (Ubuntu 8.04)
- openoffice.org-help-en-gb-2.4.1-1ubuntu2.1 (Ubuntu 8.04)
- openoffice.org-help-en-us-2.4.1-1ubuntu2.1 (Ubuntu 8.04)
- openoffice.org-help-es-2.4.1-1ubuntu2.1 (Ubuntu 8.04)
- openoffice.org-help-et-2.4.1-1ubuntu2.1 (
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-2237","CVE-2008-2238","CVE-2008-4937");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-br", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-br-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-br-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-cs", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-cs-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-cs-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-da", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-da-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-da-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-de", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-de-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-de-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-dz", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-dz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-dz-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-en-gb", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-en-gb-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-en-gb-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-en-us", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-en-us-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-en-us-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-es", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-es-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-es-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-et", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-et-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-et-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-eu", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-eu-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-eu-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-fr", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-fr-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-fr-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-gl", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-gl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-gl-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-hi-in", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-hi-in-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-hi-in-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-hu", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-hu-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-hu-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-it", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-it-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-it-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-ja", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-ja-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-ja-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-km", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-km-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-km-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-ko", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-ko-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-ko-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-nl", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-nl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-nl-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-pl", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-pl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-pl-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-pt", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-pt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-pt-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-pt-br", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-pt-br-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-pt-br-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-ru", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-ru-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-ru-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-sl", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-sl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-sl-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-sv", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-sv-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-sv-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-zh-cn", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-zh-cn-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-zh-cn-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-help-zh-tw", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-help-zh-tw-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-help-zh-tw-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-af", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-af-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-af-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ar", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ar-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ar-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-as-in", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-as-in-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-as-in-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-be-by", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-be-by-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-be-by-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-bg", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-bg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-bg-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-bn", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-bn-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-bn-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-br", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-br-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-br-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-bs", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-bs-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-bs-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ca", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ca-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ca-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-common", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-common-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-common-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-cs", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-cs-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-cs-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-cy", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-cy-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-cy-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-da", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-da-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-da-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-de", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-de-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-de-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-dz", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-dz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-dz-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-el", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-el-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-el-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-en-gb", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-en-gb-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-en-gb-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-en-za", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-en-za-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-en-za-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-eo", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-eo-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-eo-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-es", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-es-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-es-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-et", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-et-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-et-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-eu", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-eu-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-eu-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-fa", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-fa-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-fa-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-fi", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-fi-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-fi-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-fr", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-fr-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-fr-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ga", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ga-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ga-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-gl", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-gl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-gl-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-gu-in", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-gu-in-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-gu-in-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-he", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-he-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-he-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-hi-in", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-hi-in-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-hi-in-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-hr", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-hr-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-hr-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-hu", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-hu-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-hu-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-it", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-it-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-it-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ja", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ja-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ja-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ka", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ka-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ka-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-km", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-km-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-km-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-kn", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-kn-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-kn-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ko", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ko-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ko-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ku", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ku-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ku-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-lo", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-lo-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-lo-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-lt", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-lt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-lt-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-lv", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-lv-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-lv-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-mk", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-mk-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-mk-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ml-in", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ml-in-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ml-in-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-mr-in", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-mr-in-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-mr-in-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-nb", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-nb-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-nb-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ne", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ne-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ne-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-nl", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-nl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-nl-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-nn", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-nn-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-nn-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-nr", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-nr-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-nr-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ns", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ns-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ns-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-or-in", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-or-in-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-or-in-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-pa-in", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-pa-in-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-pa-in-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-pl", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-pl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-pl-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-pt", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-pt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-pt-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-pt-br", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-pt-br-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-pt-br-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ro", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ro-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ro-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ru", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ru-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ru-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-rw", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-rw-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-rw-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-sk", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-sk-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-sk-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-sl", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-sl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-sl-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-sr", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-sr-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-sr-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ss", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ss-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ss-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-st", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-st-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-st-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-sv", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-sv-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-sv-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-sw", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-sw-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-sw-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ta-in", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ta-in-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ta-in-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-te-in", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-te-in-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-te-in-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-tg", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-tg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-tg-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-th", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-th-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-th-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ti-er", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ti-er-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ti-er-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-tn", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-tn-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-tn-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-tr", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-tr-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-tr-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ts", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ts-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ts-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-uk", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-uk-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-uk-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ur-in", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ur-in-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ur-in-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-uz", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-uz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-uz-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-ve", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-ve-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-ve-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-vi", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-vi-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-vi-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-xh", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-xh-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-xh-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-zh-cn", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-zh-cn-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-zh-cn-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-zh-tw", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-zh-tw-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-zh-tw-2.4.1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openoffice.org-l10n-zu", pkgver: "2.4.1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org-l10n-zu-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openoffice.org-l10n-zu-2.4.1-1ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
