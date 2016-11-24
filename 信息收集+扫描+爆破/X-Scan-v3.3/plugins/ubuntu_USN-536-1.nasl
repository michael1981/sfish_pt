# This script was automatically generated from the 536-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28142);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "536-1");
script_summary(english:"Thunderbird vulnerabilities");
script_name(english:"USN536-1 : Thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- mozilla-thunderbird-inspector 
- mozilla-thunderbird-typeaheadfind 
');
script_set_attribute(attribute:'description', value: 'Various flaws were discovered in the layout and JavaScript engines. By
tricking a user into opening a malicious web page, an attacker could
execute arbitrary code with the user\'s privileges. (CVE-2007-5339,
CVE-2007-5340)

Flaws were discovered in the file upload form control. By tricking
a user into opening a malicious web page, an attacker could force
arbitrary files from the user\'s computer to be uploaded without their
consent. (CVE-2006-2894, CVE-2007-3511)

Michal Zalewski discovered that the onUnload event handlers were
incorrectly able to access information outside the old page content. A
malicious web site could exploit this to modify the contents, or
steal confidential data (such as passwords), of the next loaded web
page. (CVE-2007-1095)

Stefano Di Paola discovered that Thunderbird did not correctly request
Digest Authentications. A malicious web site could exploit this to
inject arbitrary HTTP headers or perform session splitting attacks
against proxies. (CVE-2007-2292)

Eli Friedman discovered
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-1.5.0.13+1.5.0.14b-0ubuntu0.7.04 (Ubuntu 7.04)
- mozilla-thunderbird-dev-1.5.0.13+1.5.0.14b-0ubuntu0.7.04 (Ubuntu 7.04)
- mozilla-thunderbird-inspector-1.5.0.13+1.5.0.14b-0ubuntu0.7.04 (Ubuntu 7.04)
- mozilla-thunderbird-typeaheadfind-1.5.0.13+1.5.0.14b-0ubuntu0.7.04 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-2894","CVE-2007-1095","CVE-2007-2292","CVE-2007-3511","CVE-2007-5334","CVE-2007-5337","CVE-2007-5338","CVE-2007-5339","CVE-2007-5340");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "mozilla-thunderbird", pkgver: "1.5.0.13+1.5.0.14b-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-thunderbird-1.5.0.13+1.5.0.14b-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-thunderbird-dev", pkgver: "1.5.0.13+1.5.0.14b-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-thunderbird-dev-1.5.0.13+1.5.0.14b-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-thunderbird-inspector", pkgver: "1.5.0.13+1.5.0.14b-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-inspector-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-thunderbird-inspector-1.5.0.13+1.5.0.14b-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-thunderbird-typeaheadfind", pkgver: "1.5.0.13+1.5.0.14b-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-typeaheadfind-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-thunderbird-typeaheadfind-1.5.0.13+1.5.0.14b-0ubuntu0.7.04
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
