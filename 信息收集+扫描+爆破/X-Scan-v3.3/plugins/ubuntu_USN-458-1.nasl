# This script was automatically generated from the 458-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28056);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "458-1");
script_summary(english:"MoinMoin vulnerabilities");
script_name(english:"USN458-1 : MoinMoin vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- moinmoin-common 
- python-moinmoin 
- python2.4-moinmoin 
');
script_set_attribute(attribute:'description', value: 'A flaw was discovered in MoinMoin\'s error reporting when using the 
AttachFile action.  By tricking a user into viewing a crafted MoinMoin 
URL, an attacker could execute arbitrary JavaScript as the current 
MoinMoin user, possibly exposing the user\'s authentication information 
for the domain where MoinMoin was hosted. (CVE-2007-2423)

Flaws were discovered in MoinMoin\'s ACL handling for calendars and 
includes.  Unauthorized users would be able to read pages that would 
otherwise be unavailable to them.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- moinmoin-common-1.5.3-1.1ubuntu3.1 (Ubuntu 7.04)
- python-moinmoin-1.5.3-1.1ubuntu3.1 (Ubuntu 7.04)
- python2.4-moinmoin-1.5.3-1ubuntu1.3 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2007-2423");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "moinmoin-common", pkgver: "1.5.3-1.1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package moinmoin-common-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to moinmoin-common-1.5.3-1.1ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "python-moinmoin", pkgver: "1.5.3-1.1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-moinmoin-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to python-moinmoin-1.5.3-1.1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "python2.4-moinmoin", pkgver: "1.5.3-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-moinmoin-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to python2.4-moinmoin-1.5.3-1ubuntu1.3
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
