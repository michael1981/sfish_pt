# This script was automatically generated from the 200-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20616);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "200-1");
script_summary(english:"mozilla-thunderbird vulnerabilities");
script_name(english:"USN200-1 : mozilla-thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-enigmail 
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- mozilla-thunderbird-enigmail 
- mozilla-thunderbird-inspector 
- mozilla-thunderbird-offline 
- mozilla-thunderbird-typeaheadfind 
');
script_set_attribute(attribute:'description', value: 'A buffer overflow was discovered in the XBM image handler. By tricking
an user into opening a specially crafted XBM image, an attacker could
exploit this to execute arbitrary code with the user\'s privileges.
(CVE-2005-2701)

Mats Palmgren discovered a buffer overflow in the Unicode string
parser. Unicode strings that contained "zero-width non-joiner"
characters caused a browser crash, which could possibly even exploited
to execute arbitrary code with the user\'s privileges.
(CVE-2005-2702)

Georgi Guninski reported an integer overflow in the JavaScript engine.
This could be exploited to run arbitrary code under some conditions.
(CVE-2005-2705)

Peter Zelezny discovered that URLs which are passed to Thunderbird on the
command line are not correctly protected against interpretation by the shell.
If Thunderbird is configured as the default handler for "mailto:" URLs, this
could be exploited to execute arbitrary code with user privileges by tricking
the user into clicking on a specially crafted URL (for example
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-enigmail-0.92-1ubuntu05.04.2 (Ubuntu 5.04)
- mozilla-thunderbird-1.0.7-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-thunderbird-dev-1.0.7-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-thunderbird-enigmail-0.92-1ubuntu05.04.2 (Ubuntu 5.04)
- mozilla-thunderbird-inspector-1.0.7-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-thunderbird-offline-1.0.7-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-thunderbird-typeaheadfind-1.0.7-0ubuntu05.04 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-2701","CVE-2005-2702","CVE-2005-2703","CVE-2005-2704","CVE-2005-2705","CVE-2005-2706","CVE-2005-2707","CVE-2005-2968");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "mozilla-enigmail", pkgver: "0.92-1ubuntu05.04.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-enigmail-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-enigmail-0.92-1ubuntu05.04.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-thunderbird", pkgver: "1.0.7-0ubuntu05.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-thunderbird-1.0.7-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-thunderbird-dev", pkgver: "1.0.7-0ubuntu05.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-thunderbird-dev-1.0.7-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-thunderbird-enigmail", pkgver: "0.92-1ubuntu05.04.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-enigmail-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-thunderbird-enigmail-0.92-1ubuntu05.04.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-thunderbird-inspector", pkgver: "1.0.7-0ubuntu05.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-inspector-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-thunderbird-inspector-1.0.7-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-thunderbird-offline", pkgver: "1.0.7-0ubuntu05.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-offline-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-thunderbird-offline-1.0.7-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-thunderbird-typeaheadfind", pkgver: "1.0.7-0ubuntu05.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-typeaheadfind-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-thunderbird-typeaheadfind-1.0.7-0ubuntu05.04
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
