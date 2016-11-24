# This script was automatically generated from the 206-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20622);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "206-1");
script_summary(english:"lynx vulnerability");
script_name(english:"USN206-1 : lynx vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "lynx" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Ulf Harnhammar discovered a remote vulnerability in Lynx when
connecting to a news server (NNTP). The function that added missing
escape chararacters to article headers did not check the size of the
target buffer. Specially crafted news entries could trigger a buffer
overflow, which could be exploited to execute arbitrary code with the
privileges of the user running lynx. In order to exploit this, the
user is not even required to actively visit a news site with Lynx
since a malicious HTML page could automatically redirect to an nntp://
URL with malicious news items.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- lynx-2.8.5-2ubuntu0.5.10 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-3120");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "lynx", pkgver: "2.8.5-2ubuntu0.5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lynx-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to lynx-2.8.5-2ubuntu0.5.10
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
