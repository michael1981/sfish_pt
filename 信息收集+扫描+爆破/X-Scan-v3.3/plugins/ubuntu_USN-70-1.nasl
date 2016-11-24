# This script was automatically generated from the 70-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20691);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "70-1");
script_summary(english:"libdbi-perl vulnerabilities");
script_name(english:"USN70-1 : libdbi-perl vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "libdbi-perl" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Javier Fernández-Sanguino Peña from the Debian Security Audit Project
discovered that the module DBI::ProxyServer in Perl\'s DBI library
created a PID file in an insecure manner. This could allow a symbolic
link attack to create or overwrite arbitrary files with the privileges
of the user invoking a program using this module (like \'dbiproxy\').

Now the module does not create a such a PID file by default.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libdbi-perl-1.42-3ubuntu0.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2005-0077");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "libdbi-perl", pkgver: "1.42-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbi-perl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libdbi-perl-1.42-3ubuntu0.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
