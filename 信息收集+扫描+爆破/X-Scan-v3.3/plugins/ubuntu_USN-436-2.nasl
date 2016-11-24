# This script was automatically generated from the 436-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28032);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "436-2");
script_summary(english:"KTorrent vulnerability");
script_name(english:"USN436-2 : KTorrent vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "ktorrent" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'USN-436-1 fixed a vulnerability in KTorrent.  The original fix for path 
traversal was incomplete, allowing for alternate vectors of attack.  
This update solves the problem.

Original advisory details:

 Bryan Burns of Juniper Networks discovered that KTorrent did not 
 correctly validate the destination file paths nor the HAVE statements 
 sent by torrent peers. A malicious remote peer could send specially 
 crafted messages to overwrite files or execute arbitrary code with user 
 privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ktorrent-2.1-0ubuntu2.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-1799");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "ktorrent", pkgver: "2.1-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ktorrent-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to ktorrent-2.1-0ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
