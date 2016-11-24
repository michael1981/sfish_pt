# This script was automatically generated from the 492-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28094);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "492-1");
script_summary(english:"tcpdump vulnerability");
script_name(english:"USN492-1 : tcpdump vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "tcpdump" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'A flaw was discovered in the BGP dissector of tcpdump.  Remote
attackers could send specially crafted packets and execute arbitrary
code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- tcpdump-3.9.5-2ubuntu1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-3798");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "tcpdump", pkgver: "3.9.5-2ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tcpdump-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to tcpdump-3.9.5-2ubuntu1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
