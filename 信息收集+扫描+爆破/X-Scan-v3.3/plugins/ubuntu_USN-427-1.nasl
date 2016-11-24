# This script was automatically generated from the 427-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28020);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "427-1");
script_summary(english:"enigmail vulnerability");
script_name(english:"USN427-1 : enigmail vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "mozilla-thunderbird-enigmail" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Mikhail Markin reported that enigmail incorrectly handled memory
allocations for certain large encrypted attachments. This caused
Thunderbird to crash and thus caused the entire message to be
inaccessible.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-enigmail-0.94-0ubuntu5.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2006-5877");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "mozilla-thunderbird-enigmail", pkgver: "0.94-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-enigmail-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mozilla-thunderbird-enigmail-0.94-0ubuntu5.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
