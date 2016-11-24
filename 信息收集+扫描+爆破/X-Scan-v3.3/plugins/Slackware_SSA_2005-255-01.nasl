# This script was automatically generated from the SSA-2005-255-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(19864);
script_version("$Revision: 1.4 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2005-255-01 security update');
script_set_attribute(attribute:'description', value: '
New dhcpcd packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, and -current to fix a minor security issue.  The dhcpcd daemon
can be tricked into reading past the end of the DHCP buffer by a
malicious DHCP server, which causes the dhcpcd daemon to crash and
results in a denial of service.  Of course, a malicious DHCP server
could simply give you an IP address that wouldn\'t work, too, such as
127.0.0.1, but since people have been asking about this issue, here\'s
a fix, and that\'s the extent of the impact.  In other words, very
little real impact.

Even less detail about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1848

');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2005-255-01");
script_summary("SSA-2005-255-01 dhcpcd DoS ");
script_name(english: "SSA-2005-255-01 dhcpcd DoS ");
script_cve_id("CVE-2005-1848");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "dhcpcd", pkgver: "1.3.22pl4", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package dhcpcd is vulnerable in Slackware 8.1
Upgrade to dhcpcd-1.3.22pl4-i386-2 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "dhcpcd", pkgver: "1.3.22pl4", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package dhcpcd is vulnerable in Slackware 9.0
Upgrade to dhcpcd-1.3.22pl4-i386-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "dhcpcd", pkgver: "1.3.22pl4", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package dhcpcd is vulnerable in Slackware 9.1
Upgrade to dhcpcd-1.3.22pl4-i486-2 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "dhcpcd", pkgver: "1.3.22pl4", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package dhcpcd is vulnerable in Slackware 10.0
Upgrade to dhcpcd-1.3.22pl4-i486-2 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "dhcpcd", pkgver: "1.3.22pl4", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package dhcpcd is vulnerable in Slackware 10.1
Upgrade to dhcpcd-1.3.22pl4-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "dhcpcd", pkgver: "1.3.22pl4", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package dhcpcd is vulnerable in Slackware -current
Upgrade to dhcpcd-1.3.22pl4-i486-2 or newer.
');
}

if (w) { security_warning(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
