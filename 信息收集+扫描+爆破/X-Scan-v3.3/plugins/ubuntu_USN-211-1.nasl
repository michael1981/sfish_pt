# This script was automatically generated from the 211-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20629);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "211-1");
script_summary(english:"enigmail vulnerability");
script_name(english:"USN211-1 : enigmail vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-enigmail 
- mozilla-thunderbird-enigmail 
');
script_set_attribute(attribute:'description', value: 'Hadmut Danish discovered an information disclosure vulnerability in
the key selection dialog of the Mozilla/Thunderbird enigmail plugin.
If a user\'s keyring contained a key with an empty user id (i. e. a
key without a name and email address), this key was selected by
default when the user attempted to send an encrypted email. Unless
this empty key was manually deselected, the message got encrypted for
that empty key, whose owner could then decrypt it.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-enigmail-0.92.1-0ubuntu05.10 (Ubuntu 5.10)
- mozilla-thunderbird-enigmail-0.92.1-0ubuntu05.10 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2005-3256");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "mozilla-enigmail", pkgver: "0.92.1-0ubuntu05.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-enigmail-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-enigmail-0.92.1-0ubuntu05.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-enigmail", pkgver: "0.92.1-0ubuntu05.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-enigmail-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-enigmail-0.92.1-0ubuntu05.10
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
