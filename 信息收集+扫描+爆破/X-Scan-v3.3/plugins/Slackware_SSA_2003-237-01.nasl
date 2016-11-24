# This script was automatically generated from the SSA-2003-237-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18722);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2003-237-01 security update');
script_set_attribute(attribute:'description', value: '
Upgraded infozip packages are available for Slackware 9.0 and -current.
These fix a security issue where a specially crafted archive may
overwrite files (including system files anywhere on the filesystem)
upon extraction by a user with sufficient permissions.

For more information, see:

http://www.securityfocus.com/bid/7550
http://lwn.net/Articles/38540/
http://xforce.iss.net/xforce/xfdb/12004
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0282


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2003-237-01");
script_summary("SSA-2003-237-01 unzip vulnerability patched ");
script_name(english: "SSA-2003-237-01 unzip vulnerability patched ");
script_cve_id("CVE-2003-0282");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "9.0", pkgname: "infozip", pkgver: "5.50", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package infozip is vulnerable in Slackware 9.0
Upgrade to infozip-5.50-i386-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "infozip", pkgver: "5.50", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package infozip is vulnerable in Slackware -current
Upgrade to infozip-5.50-i486-2 or newer.
');
}

if (w) { security_note(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
