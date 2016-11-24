# This script was automatically generated from the 373-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27954);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "373-1");
script_summary(english:"mutt vulnerabilities");
script_name(english:"USN373-1 : mutt vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "mutt" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Race conditions were discovered in mutt\'s handling of temporary files.  
Under certain conditions when using a shared temp directory (the 
default), other local users could overwrite arbitrary files owned by the 
user running mutt.  This vulnerability is more likely when the temp 
directory is over NFS.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mutt-1.5.12-1ubuntu1.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2006-5297","CVE-2006-5298");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "mutt", pkgver: "1.5.12-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mutt-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mutt-1.5.12-1ubuntu1.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
