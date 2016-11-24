# This script was automatically generated from the SSA-2004-108-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18765);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-108-02 security update');
script_set_attribute(attribute:'description', value: '
CVS is a client/server version control system.  As a server, it
is used to host source code repositories.  As a client, it is
used to access such repositories.  This advisory affects both uses
of CVS.

A security problem which could allow a server to create arbitrary
files on a client machine, and another security problem which may
allow a client to view files outside of the CVS repository have
been fixed with the release of cvs-1.11.15.

Any sites running CVS should upgrade to the new CVS package.


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-108-02");
script_summary("SSA-2004-108-02 cvs security update ");
script_name(english: "SSA-2004-108-02 cvs security update ");
script_cve_id("CVE-2004-0180","CVE-2004-0405");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "cvs", pkgver: "1.11.15", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package cvs is vulnerable in Slackware 8.1
Upgrade to cvs-1.11.15-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "cvs", pkgver: "1.11.15", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package cvs is vulnerable in Slackware 9.0
Upgrade to cvs-1.11.15-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "cvs", pkgver: "1.11.15", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package cvs is vulnerable in Slackware 9.1
Upgrade to cvs-1.11.15-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "cvs", pkgver: "1.11.15", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package cvs is vulnerable in Slackware -current
Upgrade to cvs-1.11.15-i486-1 or newer.
');
}

if (w) { security_warning(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
