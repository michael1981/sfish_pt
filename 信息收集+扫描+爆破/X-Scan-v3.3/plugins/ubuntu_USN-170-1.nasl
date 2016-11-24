# This script was automatically generated from the 170-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20577);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "170-1");
script_summary(english:"gnupg vulnerability");
script_name(english:"USN170-1 : gnupg vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gnupg" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Serge Mister and Robert Zuccherato discovered a weakness of the
symmetrical encryption algorithm of gnupg. When decrypting a message,
gnupg uses a feature called "quick scan"; this can quickly check
whether the key that is used for decryption is (probably) the right
one, so that wrong keys can be determined quickly without decrypting
the whole message.

A failure of the quick scan will be determined much faster than a
successful one.  Mister/Zuccherato demonstrated that this timing
difference can be exploited to an attack which allows an attacker to
decrypt parts of an encrypted message if an "oracle" is available, i.
e. an automatic system that receives random encrypted messages from
the attacker and answers whether it passes the quick scan check.

However, since the attack requires a huge amount of oracle answers
(about 32.000 for every 16 bytes of ciphertext), this attack is mostly
theoretical. It does not have any impact on human operation of gnupg
and is not believed to be exploitable in practice.

The 
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gnupg-1.2.5-3ubuntu5.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2005-0366");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "gnupg", pkgver: "1.2.5-3ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnupg-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gnupg-1.2.5-3ubuntu5.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
