# This script was automatically generated from the 242-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20789);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "242-1");
script_summary(english:"mailman vulnerabilities");
script_name(english:"USN242-1 : mailman vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "mailman" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Aliet Santiesteban Sifontes discovered a remote Denial of Service
vulnerability in the attachment handler. An email with an attachment
whose filename contained invalid UTF-8 characters caused mailman to
crash. (CVE-2005-3573)

Mailman did not sufficiently verify the validity of email dates. Very
large numbers in dates caused mailman to crash. (CVE-2005-4153)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mailman-2.1.5-8ubuntu2.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2005-3573","CVE-2005-4153");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "mailman", pkgver: "2.1.5-8ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mailman-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mailman-2.1.5-8ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
