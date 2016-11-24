# This script was automatically generated from the 774-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38741);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "774-1");
script_summary(english:"moin vulnerability");
script_name(english:"USN774-1 : moin vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "python-moinmoin" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'It was discovered that MoinMoin did not properly sanitize its input when
attaching files, resulting in cross-site scripting (XSS) vulnerabilities.
With cross-site scripting vulnerabilities, if a user were tricked into
viewing server output during a crafted server request, a remote attacker
could exploit this to modify the contents, or steal confidential data,
within the same domain.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- python-moinmoin-1.8.2-2ubuntu2.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2009-1482");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "python-moinmoin", pkgver: "1.8.2-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-moinmoin-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to python-moinmoin-1.8.2-2ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
