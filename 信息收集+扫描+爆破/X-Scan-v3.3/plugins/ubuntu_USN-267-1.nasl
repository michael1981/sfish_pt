# This script was automatically generated from the 267-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21184);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "267-1");
script_summary(english:"mailman vulnerability");
script_name(english:"USN267-1 : mailman vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "mailman" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'A remote Denial of Service vulnerability was discovered in the decoder
for multipart messages. Certain parts of type "message/delivery-status"
or parts containing only two blank lines triggered an exception. An
attacker could exploit this to crash Mailman by sending a
specially crafted email to a mailing list.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mailman-2.1.5-8ubuntu2.2 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-0052");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "mailman", pkgver: "2.1.5-8ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mailman-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mailman-2.1.5-8ubuntu2.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
