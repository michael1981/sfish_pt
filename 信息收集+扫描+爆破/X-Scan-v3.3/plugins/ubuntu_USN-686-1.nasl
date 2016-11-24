# This script was automatically generated from the 686-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36652);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "686-1");
script_summary(english:"awstats vulnerability");
script_name(english:"USN686-1 : awstats vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "awstats" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Morgan Todd discovered that AWStats did not correctly strip quotes from
certain parameters, allowing for an XSS attack when running as a CGI.
If a user was tricked by a remote attacker into following a specially
crafted URL, the user\'s authentication information could be exposed for
the domain where AWStats was hosted.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- awstats-6.7.dfsg-5ubuntu0.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2008-3714");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "awstats", pkgver: "6.7.dfsg-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package awstats-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to awstats-6.7.dfsg-5ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
