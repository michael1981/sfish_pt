# This script was automatically generated from the 167-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20573);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "167-1");
script_summary(english:"awstats vulnerability");
script_name(english:"USN167-1 : awstats vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "awstats" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Peter Vreugdenhil discovered a command injection vulnerability in
AWStats. As part of the statistics reporting function, AWStats
displays information about the most common referrer values that caused
users to visit the website. Referer URLs could be crafted in a way
that they contained arbitrary Perl code which would have been executed
with the privileges of the web server as soon as some user visited the
referrer statistics page.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- awstats-6.3-1ubuntu0.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2005-1527");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "awstats", pkgver: "6.3-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package awstats-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to awstats-6.3-1ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
