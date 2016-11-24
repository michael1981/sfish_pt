# This script was automatically generated from the 532-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28138);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "532-1");
script_summary(english:"nagios-plugins vulnerability");
script_name(english:"USN532-1 : nagios-plugins vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- nagios-plugins 
- nagios-plugins-basic 
- nagios-plugins-standard 
');
script_set_attribute(attribute:'description', value: 'Nobuhiro Ban discovered that check_http in nagios-plugins did
not properly sanitize its input when following redirection
requests. A malicious remote web server could cause a denial
of service or possibly execute arbitrary code as the user.
(CVE-2007-5198)

Aravind Gottipati discovered that sslutils.c in nagios-plugins
did not properly reset pointers to NULL. A malicious remote web
server could cause a denial of service.

Aravind Gottipati discovered that check_http in nagios-plugins
did not properly calculate how much memory to reallocate when
following redirection requests. A malicious remote web server
could cause a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- nagios-plugins-1.4.2-5ubuntu3.1 (Ubuntu 6.06)
- nagios-plugins-basic-1.4.2-5ubuntu3.1 (Ubuntu 6.06)
- nagios-plugins-standard-1.4.2-5ubuntu3.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-5198");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "nagios-plugins", pkgver: "1.4.2-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios-plugins-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nagios-plugins-1.4.2-5ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nagios-plugins-basic", pkgver: "1.4.2-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios-plugins-basic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nagios-plugins-basic-1.4.2-5ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nagios-plugins-standard", pkgver: "1.4.2-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios-plugins-standard-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nagios-plugins-standard-1.4.2-5ubuntu3.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
