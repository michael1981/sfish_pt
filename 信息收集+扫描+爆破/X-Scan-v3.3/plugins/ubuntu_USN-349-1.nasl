# This script was automatically generated from the 349-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27929);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "349-1");
script_summary(english:"gzip vulnerabilities");
script_name(english:"USN349-1 : gzip vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gzip" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Tavis Ormandy discovered that gzip did not sufficiently verify the
validity of gzip or compress archives while unpacking. By tricking an
user or automated system into unpacking a specially crafted compressed
file, this could be exploited to execute arbitrary code with the
user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gzip-1.3.5-12ubuntu0.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4334","CVE-2006-4335","CVE-2006-4336","CVE-2006-4337","CVE-2006-4338");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "gzip", pkgver: "1.3.5-12ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gzip-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gzip-1.3.5-12ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
