# This script was automatically generated from the SSA-2006-130-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21346);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2006-130-01 security update');
script_set_attribute(attribute:'description', value: '
New Apache packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
10.2, and -current to fix a bug with Apache 1.3.35 and glibc that
breaks wildcards in Include directives.  It may not occur with all
versions of glibc, but it has been verified on -current (using an Include
within a file already Included causes a crash), so better to patch it
and reissue these packages just to be sure.  My apologies if the last
batch of updates caused anyone undue grief...  they worked here with my
(too simple?) config files.

Note that if you use mod_ssl, you\'ll also require the mod_ssl package
that was part of yesterday\'s release, and on -current you\'ll need the
newest PHP package (if you use PHP).

Thanks to Francesco Gringoli for bringing this issue to my attention.


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2006-130-01");
script_summary("SSA-2006-130-01 Apache httpd redux ");
script_name(english: "SSA-2006-130-01 Apache httpd redux ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "apache", pkgver: "1.3.35", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package apache is vulnerable in Slackware 8.1
Upgrade to apache-1.3.35-i386-2_slack8.1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "apache", pkgver: "1.3.35", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package apache is vulnerable in Slackware 9.0
Upgrade to apache-1.3.35-i386-2_slack9.0 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "apache", pkgver: "1.3.35", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package apache is vulnerable in Slackware 9.1
Upgrade to apache-1.3.35-i486-2_slack9.1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "apache", pkgver: "1.3.35", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package apache is vulnerable in Slackware 10.0
Upgrade to apache-1.3.35-i486-2_slack10.0 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "apache", pkgver: "1.3.35", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package apache is vulnerable in Slackware 10.1
Upgrade to apache-1.3.35-i486-2_slack10.1 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "apache", pkgver: "1.3.35", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package apache is vulnerable in Slackware 10.2
Upgrade to apache-1.3.35-i486-2_slack10.2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "apache", pkgver: "1.3.35", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package apache is vulnerable in Slackware -current
Upgrade to apache-1.3.35-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
