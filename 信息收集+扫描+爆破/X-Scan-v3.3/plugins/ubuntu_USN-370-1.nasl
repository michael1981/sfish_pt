# This script was automatically generated from the 370-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27951);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "370-1");
script_summary(english:"screen vulnerability");
script_name(english:"USN370-1 : screen vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "screen" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'cstone and Rich Felker discovered a programming error in the UTF8 string 
handling code of "screen" leading to a denial of service.  If a crafted 
string was displayed within a screen session, screen would crash or 
possibly execute arbitrary code.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- screen-4.0.2-4.1ubuntu5.6.10 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4573");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "screen", pkgver: "4.0.2-4.1ubuntu5.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package screen-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to screen-4.0.2-4.1ubuntu5.6.10
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
