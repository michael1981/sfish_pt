# This script was automatically generated from the 290-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27862);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "290-1");
script_summary(english:"awstats vulnerability");
script_name(english:"USN290-1 : awstats vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "awstats" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Hendrik Weimer discovered a privilege escalation vulnerability in
awstats. By supplying the \'configdir\' CGI parameter and setting it to
an attacker-controlled directory (such as an FTP account, /tmp, or
similar), an attacker could execute arbitrary shell commands with the
privileges of the web server (user \'www-data\').

This update disables the \'configdir\' parameter by default. If all
local user accounts can be trusted, it can be reenabled by running
awstats with the AWSTATS_ENABLE_CONFIG_DIR environment variable set to
a nonempty value.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- awstats-6.5-1ubuntu1.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2006-2644");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "awstats", pkgver: "6.5-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package awstats-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to awstats-6.5-1ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
