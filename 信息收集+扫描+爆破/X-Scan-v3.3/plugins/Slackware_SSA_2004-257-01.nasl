# This script was automatically generated from the SSA-2004-257-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18757);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-257-01 security update');
script_set_attribute(attribute:'description', value: '
New samba packages are available for Slackware 10.0 and -current.
These fix two denial of service vulnerabilities reported by
iDEFENSE.  Slackware -current has been upgraded to samba-3.0.7,
while the samba-3.0.5 included with Slackware 10.0 has been
patched to fix these issues.  Sites running Samba 3.x should
upgrade to the new package.  Versions of Samba before 3.0.x are
not affected by these flaws.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0807
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0808


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-257-01");
script_summary("SSA-2004-257-01 samba DoS ");
script_name(english: "SSA-2004-257-01 samba DoS ");
script_cve_id("CVE-2004-0807","CVE-2004-0808");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "10.0", pkgname: "samba", pkgver: "3.0.5", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package samba is vulnerable in Slackware 10.0
Upgrade to samba-3.0.5-i486-3 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "samba", pkgver: "3.0.7", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package samba is vulnerable in Slackware -current
Upgrade to samba-3.0.7-i486-1 or newer.
');
}

if (w) { security_warning(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
