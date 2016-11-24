# This script was automatically generated from the SSA-2004-108-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18783);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-108-01 security update');
script_set_attribute(attribute:'description', value: '
Upgraded tcpdump packages are available for Slackware 8.1, 9.0,
9.1, and -current to fix denial-of-service issues.  Sites using
tcpdump should upgrade to the new packages.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0183
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0184

The tcpdump advisory from Rapid7 may be found here:
  http://www.rapid7.com/advisories/R7-0017.html

');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-108-01");
script_summary("SSA-2004-108-01 tcpdump denial of service ");
script_name(english: "SSA-2004-108-01 tcpdump denial of service ");
script_cve_id("CVE-2004-0183","CVE-2004-0184");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "tcpdump", pkgver: "3.8.3", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package tcpdump is vulnerable in Slackware 8.1
Upgrade to tcpdump-3.8.3-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "tcpdump", pkgver: "3.8.3", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package tcpdump is vulnerable in Slackware 9.0
Upgrade to tcpdump-3.8.3-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "tcpdump", pkgver: "3.8.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package tcpdump is vulnerable in Slackware 9.1
Upgrade to tcpdump-3.8.3-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "tcpdump", pkgver: "3.8.3", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package tcpdump is vulnerable in Slackware -current
Upgrade to tcpdump-3.8.3-i486-2 or newer.
');
}

if (w) { security_warning(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
