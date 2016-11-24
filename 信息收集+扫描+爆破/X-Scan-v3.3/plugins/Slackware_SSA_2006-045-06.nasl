# This script was automatically generated from the SSA-2006-045-06
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20917);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2006-045-06 security update');
script_set_attribute(attribute:'description', value: 'Several security updates are now available for Slackware 8.1, including
updated packages for Apache, glibc, mod_ssl, openssh, openssl, and php.

');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2006-045-06");
script_summary("SSA-2006-045-06 Security updates for Slackware 8.1");
script_name(english: "SSA-2006-045-06 Security updates for Slackware 8.1");
script_cve_id("CVE-2002-0653","CVE-2002-0658","CVE-2002-0659");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "apache", pkgver: "1.3.26", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package apache is vulnerable in Slackware 8.1
Upgrade to apache-1.3.26-i386-2 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "glibc", pkgver: "2.2.5", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc is vulnerable in Slackware 8.1
Upgrade to glibc-2.2.5-i386-3 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "glibc-solibs", pkgver: "2.2.5", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-solibs is vulnerable in Slackware 8.1
Upgrade to glibc-solibs-2.2.5-i386-3 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "mod_ssl", pkgver: "2.8.10_1.3.26", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mod_ssl is vulnerable in Slackware 8.1
Upgrade to mod_ssl-2.8.10_1.3.26-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "openssh", pkgver: "3.4p1", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package openssh is vulnerable in Slackware 8.1
Upgrade to openssh-3.4p1-i386-2 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "openssl", pkgver: "0.9.6e", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package openssl is vulnerable in Slackware 8.1
Upgrade to openssl-0.9.6e-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "openssl-solibs", pkgver: "0.9.6e", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package openssl-solibs is vulnerable in Slackware 8.1
Upgrade to openssl-solibs-0.9.6e-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "php", pkgver: "4.2.2", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package php is vulnerable in Slackware 8.1
Upgrade to php-4.2.2-i386-1 or newer.
');
}

if (w) { security_warning(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
