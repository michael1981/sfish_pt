# This script was automatically generated from the 209-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20626);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "209-1");
script_summary(english:"openssh vulnerability");
script_name(english:"USN209-1 : openssh vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- openssh-client 
- openssh-server 
- ssh 
- ssh-askpass-gnome 
');
script_set_attribute(attribute:'description', value: 'An information disclosure vulnerability has been found in the SSH
server. When the GSSAPIAuthentication option was enabled, the SSH
server could send GSSAPI credentials even to users who attempted to
log in with a method other than GSSAPI. This could inadvertently
expose these credentials to an untrusted user.

Please note that this does not affect the default configuration of the
SSH server.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- openssh-client-3.9p1-1ubuntu2.1 (Ubuntu 5.04)
- openssh-server-3.9p1-1ubuntu2.1 (Ubuntu 5.04)
- ssh-3.9p1-1ubuntu2.1 (Ubuntu 5.04)
- ssh-askpass-gnome-3.9p1-1ubuntu2.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2005-2798");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "openssh-client", pkgver: "3.9p1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssh-client-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openssh-client-3.9p1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openssh-server", pkgver: "3.9p1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssh-server-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openssh-server-3.9p1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ssh", pkgver: "3.9p1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ssh-3.9p1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ssh-askpass-gnome", pkgver: "3.9p1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-askpass-gnome-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ssh-askpass-gnome-3.9p1-1ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
