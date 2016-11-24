# This script was automatically generated from the 307-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27882);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "307-1");
script_summary(english:"mutt vulnerability");
script_name(english:"USN307-1 : mutt vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "mutt" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'TAKAHASHI Tamotsu discovered that mutt\'s IMAP backend did not
sufficiently check the validity of namespace strings. If an user
connects to a malicious IMAP server, that server could exploit this to
crash mutt or even execute arbitrary code with the privileges of the
mutt user.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mutt-1.5.11-3ubuntu2.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "mutt", pkgver: "1.5.11-3ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mutt-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mutt-1.5.11-3ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
