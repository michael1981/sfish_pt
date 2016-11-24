# This script was automatically generated from the 716-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38011);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "716-1");
script_summary(english:"moin vulnerabilities");
script_name(english:"USN716-1 : moin vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- moinmoin-common 
- python-moinmoin 
- python2.4-moinmoin 
');
script_set_attribute(attribute:'description', value: 'Fernando Quintero discovered than MoinMoin did not properly sanitize its
input when processing login requests, resulting in cross-site scripting (XSS)
vulnerabilities. With cross-site scripting vulnerabilities, if a user were
tricked into viewing server output during a crafted server request, a remote
attacker could exploit this to modify the contents, or steal confidential data,
within the same domain. This issue affected Ubuntu 7.10 and 8.04 LTS.
(CVE-2008-0780)

Fernando Quintero discovered that MoinMoin did not properly sanitize its input
when attaching files, resulting in cross-site scripting vulnerabilities. This
issue affected Ubuntu 6.06 LTS, 7.10 and 8.04 LTS. (CVE-2008-0781)

It was discovered that MoinMoin did not properly sanitize its input when
processing user forms. A remote attacker could submit crafted cookie values and
overwrite arbitrary files via directory traversal. This issue affected Ubuntu
6.06 LTS, 7.10 and 8.04 LTS. (CVE-2008-0782)

It was discovered that MoinMoin did not properly sa
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- moinmoin-common-1.5.8-5.1ubuntu2.2 (Ubuntu 8.04)
- python-moinmoin-1.7.1-1ubuntu1.1 (Ubuntu 8.10)
- python2.4-moinmoin-1.5.2-1ubuntu2.4 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2008-0780","CVE-2008-0781","CVE-2008-0782","CVE-2008-1098","CVE-2008-1099","CVE-2009-0260","CVE-2009-0312");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "moinmoin-common", pkgver: "1.5.8-5.1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package moinmoin-common-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to moinmoin-common-1.5.8-5.1ubuntu2.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "python-moinmoin", pkgver: "1.7.1-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-moinmoin-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to python-moinmoin-1.7.1-1ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-moinmoin", pkgver: "1.5.2-1ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-moinmoin-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-moinmoin-1.5.2-1ubuntu2.4
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
