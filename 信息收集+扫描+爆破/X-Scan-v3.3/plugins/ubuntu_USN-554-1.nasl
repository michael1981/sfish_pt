# This script was automatically generated from the 554-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(29239);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "554-1");
script_summary(english:"tetex-bin, texlive-bin vulnerabilities");
script_name(english:"USN554-1 : tetex-bin, texlive-bin vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libkpathsea-dev 
- libkpathsea4 
- libkpathsea4-dev 
- tetex-bin 
- texlive-base-bin 
- texlive-extra-utils 
- texlive-font-utils 
- texlive-lang-indic 
- texlive-metapost 
- texlive-music 
- texlive-omega 
- texlive-xetex 
');
script_set_attribute(attribute:'description', value: 'Bastien Roucaries discovered that dvips as included in tetex-bin
and texlive-bin did not properly perform bounds checking. If a
user or automated system were tricked into processing a specially
crafted dvi file, dvips could be made to crash and execute code as
the user invoking the program. (CVE-2007-5935)

Joachim Schrod discovered that the dviljk utilities created
temporary files in an insecure way. Local users could exploit a
race condition to create or overwrite files with the privileges of
the user invoking the program. (CVE-2007-5936)

Joachim Schrod discovered that the dviljk utilities did not
perform bounds checking in many instances. If a user or automated
system were tricked into processing a specially crafted dvi file,
the dviljk utilities could be made to crash and execute code as
the user invoking the program. (CVE-2007-5937)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libkpathsea-dev-2007-12ubuntu3.1 (Ubuntu 7.10)
- libkpathsea4-2007-12ubuntu3.1 (Ubuntu 7.10)
- libkpathsea4-dev-3.0-13ubuntu6.1 (Ubuntu 6.06)
- tetex-bin-3.0-27ubuntu1.2 (Ubuntu 7.04)
- texlive-base-bin-2007-12ubuntu3.1 (Ubuntu 7.10)
- texlive-extra-utils-2007-12ubuntu3.1 (Ubuntu 7.10)
- texlive-font-utils-2007-12ubuntu3.1 (Ubuntu 7.10)
- texlive-lang-indic-2007-12ubuntu3.1 (Ubuntu 7.10)
- texlive-metapost-2007-12ubuntu3.1 (Ubuntu 7.10)
- texlive-music-2007-12ubuntu3.1 (Ubuntu 7.10)
- texli
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-5935","CVE-2007-5936","CVE-2007-5937");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libkpathsea-dev", pkgver: "2007-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkpathsea-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkpathsea-dev-2007-12ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libkpathsea4", pkgver: "2007-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkpathsea4-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkpathsea4-2007-12ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libkpathsea4-dev", pkgver: "3.0-13ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkpathsea4-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libkpathsea4-dev-3.0-13ubuntu6.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "tetex-bin", pkgver: "3.0-27ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tetex-bin-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to tetex-bin-3.0-27ubuntu1.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "texlive-base-bin", pkgver: "2007-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package texlive-base-bin-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to texlive-base-bin-2007-12ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "texlive-extra-utils", pkgver: "2007-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package texlive-extra-utils-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to texlive-extra-utils-2007-12ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "texlive-font-utils", pkgver: "2007-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package texlive-font-utils-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to texlive-font-utils-2007-12ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "texlive-lang-indic", pkgver: "2007-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package texlive-lang-indic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to texlive-lang-indic-2007-12ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "texlive-metapost", pkgver: "2007-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package texlive-metapost-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to texlive-metapost-2007-12ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "texlive-music", pkgver: "2007-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package texlive-music-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to texlive-music-2007-12ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "texlive-omega", pkgver: "2007-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package texlive-omega-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to texlive-omega-2007-12ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "texlive-xetex", pkgver: "2007-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package texlive-xetex-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to texlive-xetex-2007-12ubuntu3.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
