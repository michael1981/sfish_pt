# This script was automatically generated from the 387-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27970);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "387-1");
script_summary(english:"Dovecot vulnerability");
script_name(english:"USN387-1 : Dovecot vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- dovecot-common 
- dovecot-imapd 
- dovecot-pop3d 
');
script_set_attribute(attribute:'description', value: 'Dovecot was discovered to have an error when handling its index cache 
files.  This error could be exploited by authenticated POP and IMAP 
users to cause a crash of the Dovecot server, or possibly to execute 
arbitrary code.  Only servers using the non-default option 
"mmap_disable=yes" were vulnerable.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- dovecot-common-1.0.beta3-3ubuntu5.4 (Ubuntu 6.10)
- dovecot-imapd-1.0.beta3-3ubuntu5.4 (Ubuntu 6.10)
- dovecot-pop3d-1.0.beta3-3ubuntu5.4 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-5973");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "dovecot-common", pkgver: "1.0.beta3-3ubuntu5.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-common-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to dovecot-common-1.0.beta3-3ubuntu5.4
');
}
found = ubuntu_check(osver: "6.10", pkgname: "dovecot-imapd", pkgver: "1.0.beta3-3ubuntu5.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-imapd-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to dovecot-imapd-1.0.beta3-3ubuntu5.4
');
}
found = ubuntu_check(osver: "6.10", pkgname: "dovecot-pop3d", pkgver: "1.0.beta3-3ubuntu5.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-pop3d-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to dovecot-pop3d-1.0.beta3-3ubuntu5.4
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
