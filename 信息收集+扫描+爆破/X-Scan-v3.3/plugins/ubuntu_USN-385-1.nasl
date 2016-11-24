# This script was automatically generated from the 385-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27968);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "385-1");
script_summary(english:"tar vulnerability");
script_name(english:"USN385-1 : tar vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "tar" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Teemu Salmela discovered that tar still handled the deprecated 
GNUTYPE_NAMES record type.  This record type could be used to create 
symlinks that would be followed while unpacking a tar archive.  If a 
user or an automated system were tricked into unpacking a specially 
crafted tar file, arbitrary files could be overwritten with user 
privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- tar-1.15.91-2ubuntu0.3 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-6097");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "tar", pkgver: "1.15.91-2ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tar-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to tar-1.15.91-2ubuntu0.3
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
