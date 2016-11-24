# This script was automatically generated from the 376-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27957);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "376-1");
script_summary(english:"imlib2 vulnerabilities");
script_name(english:"USN376-1 : imlib2 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libimlib2 
- libimlib2-dev 
');
script_set_attribute(attribute:'description', value: 'M. Joonas Pihlaja discovered that imlib2 did not sufficiently verify the 
validity of ARGB, JPG, LBM, PNG, PNM, TGA, and TIFF images.  If a user 
were tricked into viewing or processing a specially crafted image with 
an application that uses imlib2, the flaws could be exploited to execute 
arbitrary code with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libimlib2-1.2.1-2ubuntu1.1 (Ubuntu 6.10)
- libimlib2-dev-1.2.1-2ubuntu1.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4806","CVE-2006-4807","CVE-2006-4808","CVE-2006-4809");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "libimlib2", pkgver: "1.2.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libimlib2-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libimlib2-1.2.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libimlib2-dev", pkgver: "1.2.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libimlib2-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libimlib2-dev-1.2.1-2ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
