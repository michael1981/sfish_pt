# This script was automatically generated from the 364-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27944);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "364-1");
script_summary(english:"Xsession vulnerability");
script_name(english:"USN364-1 : Xsession vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "xinit" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'A race condition existed that would allow other local users to see error 
messages generated during another user\'s X session.  This could allow 
potentially sensitive information to be leaked.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- xinit-1.0.1-0ubuntu3.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2006-5214");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "xinit", pkgver: "1.0.1-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xinit-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to xinit-1.0.1-0ubuntu3.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
