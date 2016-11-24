# This script was automatically generated from the 264-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21182);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "264-1");
script_summary(english:"gnupg vulnerability");
script_name(english:"USN264-1 : gnupg vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gnupg" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Tavis Ormandy discovered a flaw in gnupg\'s signature verification. In
some cases, certain invalid signature formats could cause gpg to
report a \'good signature\' result for auxiliary unsigned data which was
prepended or appended to the checked message part.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gnupg-1.4.1-1ubuntu1.2 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2006-0049");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "gnupg", pkgver: "1.4.1-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnupg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to gnupg-1.4.1-1ubuntu1.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
