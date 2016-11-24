# This script was automatically generated from the 586-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31603);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "586-1");
script_summary(english:"mailman vulnerability");
script_name(english:"USN586-1 : mailman vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "mailman" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Multiple cross-site scripting flaws were discovered in mailman.
A malicious list administrator could exploit this to execute arbitrary
JavaScript, potentially stealing user credentials.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mailman-2.1.9-8ubuntu0.2 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2008-0564");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "mailman", pkgver: "2.1.9-8ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mailman-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mailman-2.1.9-8ubuntu0.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
