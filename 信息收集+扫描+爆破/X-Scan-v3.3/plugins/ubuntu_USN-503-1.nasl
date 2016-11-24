# This script was automatically generated from the 503-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28107);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "503-1");
script_summary(english:"Thunderbird vulnerabilities");
script_name(english:"USN503-1 : Thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- mozilla-thunderbird-inspector 
- mozilla-thunderbird-typeaheadfind 
');
script_set_attribute(attribute:'description', value: 'Various flaws were discovered in the layout and JavaScript engines. By
tricking a user into opening a malicious email, an attacker could execute
arbitrary code with the user\'s privileges. Please note that JavaScript
is disabled by default for emails, and it is not recommended to enable it.
(CVE-2007-3734, CVE-2007-3735, CVE-2007-3844)

Jesper Johansson discovered that spaces and double-quotes were
not correctly handled when launching external programs. In rare
configurations, after tricking a user into opening a malicious email,
an attacker could execute helpers with arbitrary arguments with the
user\'s privileges. (CVE-2007-3670, CVE-2007-3845)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-1.5.0.13-0ubuntu0.7.04 (Ubuntu 7.04)
- mozilla-thunderbird-dev-1.5.0.13-0ubuntu0.7.04 (Ubuntu 7.04)
- mozilla-thunderbird-inspector-1.5.0.13-0ubuntu0.7.04 (Ubuntu 7.04)
- mozilla-thunderbird-typeaheadfind-1.5.0.13-0ubuntu0.7.04 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-3670","CVE-2007-3734","CVE-2007-3735","CVE-2007-3844","CVE-2007-3845");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "mozilla-thunderbird", pkgver: "1.5.0.13-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-thunderbird-1.5.0.13-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-thunderbird-dev", pkgver: "1.5.0.13-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-thunderbird-dev-1.5.0.13-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-thunderbird-inspector", pkgver: "1.5.0.13-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-inspector-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-thunderbird-inspector-1.5.0.13-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-thunderbird-typeaheadfind", pkgver: "1.5.0.13-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-typeaheadfind-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-thunderbird-typeaheadfind-1.5.0.13-0ubuntu0.7.04
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
