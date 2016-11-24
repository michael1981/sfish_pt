# This script was automatically generated from the 151-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20551);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "151-3");
script_summary(english:"aide vulnerabilities");
script_name(english:"USN151-3 : aide vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "aide" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'USN-148-1 and USN-151-1 fixed two security flaws in zlib, which could
be exploited to cause Denial of Service attacks or even arbitrary code
execution with malicious data streams.

Since aide is statically linked against the zlib library, it is also
affected by these issues. The updated packagages have been rebuilt
against the fixed zlib.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- aide-0.10-6.1ubuntu0.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-1849","CVE-2005-2096");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "aide", pkgver: "0.10-6.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package aide-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to aide-0.10-6.1ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
