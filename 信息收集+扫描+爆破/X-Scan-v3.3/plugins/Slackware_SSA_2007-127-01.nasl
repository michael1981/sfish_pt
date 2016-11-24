# This script was automatically generated from the SSA-2007-127-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(25174);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2007-127-01 security update');
script_set_attribute(attribute:'description', value: '
New php packages are available for Slackware 10.2, 11.0, and -current
to improve the stability and security of PHP.  Quite a few bugs were
fixed -- please see http://www.php.net for a detailed list.
All sites that use PHP are encouraged to upgrade.  Please note that
we haven\'t tested all PHP applications for backwards compatibility
with this new upgrade, so you should have the old package on hand
just in case.

Both PHP 4.4.7 and PHP 5.2.2 updates have been provided.


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2007-127-01");
script_summary("SSA-2007-127-01 php ");
script_name(english: "SSA-2007-127-01 php ");
script_cve_id("CVE-2007-1001");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "10.2", pkgname: "php", pkgver: "4.4.7", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package php is vulnerable in Slackware 10.2
Upgrade to php-4.4.7-i486-1_slack10.2 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "php", pkgver: "5.2.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package php is vulnerable in Slackware 10.2
Upgrade to php-5.2.2-i486-1_slack10.2 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "php", pkgver: "4.4.7", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package php is vulnerable in Slackware 11.0
Upgrade to php-4.4.7-i486-1_slack11.0 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "php", pkgver: "5.2.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package php is vulnerable in Slackware 11.0
Upgrade to php-5.2.2-i486-1_slack11.0 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "php", pkgver: "4.4.7", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package php is vulnerable in Slackware -current
Upgrade to php-4.4.7-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "php", pkgver: "5.2.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package php is vulnerable in Slackware -current
Upgrade to php-5.2.2-i486-1 or newer.
');
}

if (w) { security_warning(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
