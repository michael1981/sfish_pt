# This script was automatically generated from the 106-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20492);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "106-1");
script_summary(english:"gaim vulnerabilities");
script_name(english:"USN106-1 : gaim vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gaim" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Jean-Yves Lefort discovered a buffer overflow in the
gaim_markup_strip_html() function. This caused Gaim to crash when
receiving certain malformed HTML messages. (CVE-2005-0965)

Jean-Yves Lefort also noticed that many functions that handle IRC
commands do not escape received HTML metacharacters; this allowed
remote attackers to cause a Denial of Service by injecting arbitrary
HTML code into the conversation window, popping up arbitrarily many
empty dialog boxes, or even causing Gaim to crash. (CVE-2005-0966)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gaim-1.0.0-1ubuntu1.3 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-0965","CVE-2005-0966");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "gaim", pkgver: "1.0.0-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gaim-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to gaim-1.0.0-1ubuntu1.3
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
