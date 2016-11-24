# This script was automatically generated from the 360-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27940);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "360-1");
script_summary(english:"awstats vulnerabilities");
script_name(english:"USN360-1 : awstats vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "awstats" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'awstats did not fully sanitize input, which was passed directly to the user\'s
browser, allowing for an XSS attack.  If a user was tricked into following a
specially crafted awstats URL, the user\'s authentication information could be
exposed for the domain where awstats was hosted.  (CVE-2006-3681)

awstats could display its installation path under certain conditions.
However, this might only become a concern if awstats is installed into
an user\'s home directory. (CVE-2006-3682)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- awstats-6.5-1ubuntu1.2 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2006-3681","CVE-2006-3682");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "awstats", pkgver: "6.5-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package awstats-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to awstats-6.5-1ubuntu1.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
