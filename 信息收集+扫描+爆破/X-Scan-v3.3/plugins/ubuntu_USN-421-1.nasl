# This script was automatically generated from the 421-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28013);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "421-1");
script_summary(english:"MoinMoin vulnerability");
script_name(english:"USN421-1 : MoinMoin vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- moin 
- moinmoin-common 
- python-moinmoin 
- python2.3-moinmoin 
- python2.4-moinmoin 
');
script_set_attribute(attribute:'description', value: 'A flaw was discovered in MoinMoin\'s page name sanitizer which could lead 
to a cross-site scripting attack.  By tricking a user into viewing a 
crafted MoinMoin page, an attacker could execute arbitrary JavaScript as 
the current MoinMoin user, possibly exposing the user\'s authentication 
information for the domain where MoinMoin was hosted.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- moin-1.2.4-1ubuntu2.1 (Ubuntu 5.10)
- moinmoin-common-1.5.3-1ubuntu1.1 (Ubuntu 6.10)
- python-moinmoin-1.5.3-1ubuntu1.1 (Ubuntu 6.10)
- python2.3-moinmoin-1.3.4-6ubuntu1.1 (Ubuntu 5.10)
- python2.4-moinmoin-1.5.3-1ubuntu1.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2007-0857");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "moin", pkgver: "1.2.4-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package moin-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to moin-1.2.4-1ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "moinmoin-common", pkgver: "1.5.3-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package moinmoin-common-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to moinmoin-common-1.5.3-1ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "python-moinmoin", pkgver: "1.5.3-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-moinmoin-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to python-moinmoin-1.5.3-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "python2.3-moinmoin", pkgver: "1.3.4-6ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.3-moinmoin-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to python2.3-moinmoin-1.3.4-6ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "python2.4-moinmoin", pkgver: "1.5.3-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-moinmoin-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to python2.4-moinmoin-1.5.3-1ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
