# This script was automatically generated from the 158-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20562);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "158-1");
script_summary(english:"gzip vulnerability");
script_name(english:"USN158-1 : gzip vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gzip" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'zgrep did not handle shell metacharacters like \'|\' and \'&\' properly
when they occurred in input file names. This could be exploited to
execute arbitrary commands with user privileges if zgrep is run in an
untrusted directory with specially crafted file names.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gzip-1.3.5-9ubuntu3.4 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-0758");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "gzip", pkgver: "1.3.5-9ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gzip-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gzip-1.3.5-9ubuntu3.4
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
