# This script was automatically generated from the 436-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28031);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "436-1");
script_summary(english:"KTorrent vulnerabilities");
script_name(english:"USN436-1 : KTorrent vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "ktorrent" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Bryan Burns of Juniper Networks discovered that KTorrent did not 
correctly validate the destination file paths nor the HAVE statements 
sent by torrent peers.  A malicious remote peer could send specially 
crafted messages to overwrite files or execute arbitrary code with user 
privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ktorrent-2.0.3+dfsg1-0ubuntu1.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-1384","CVE-2007-1385");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "ktorrent", pkgver: "2.0.3+dfsg1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ktorrent-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to ktorrent-2.0.3+dfsg1-0ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
