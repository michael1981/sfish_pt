# This script was automatically generated from the 652-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37333);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "652-1");
script_summary(english:"lcms vulnerability");
script_name(english:"USN652-1 : lcms vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- liblcms-utils 
- liblcms1 
- liblcms1-dev 
');
script_set_attribute(attribute:'description', value: 'Chris Evans discovered that certain ICC operations in lcms were not
correctly bounds-checked.  If a user or automated system were tricked
into processing an image with malicious ICC tags, a remote attacker could
crash applications linked against liblcms1, leading to a denial of service,
or possibly execute arbitrary code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- liblcms-utils-1.13-1ubuntu0.1 (Ubuntu 6.06)
- liblcms1-1.13-1ubuntu0.1 (Ubuntu 6.06)
- liblcms1-dev-1.13-1ubuntu0.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-2741");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "liblcms-utils", pkgver: "1.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblcms-utils-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to liblcms-utils-1.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "liblcms1", pkgver: "1.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblcms1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to liblcms1-1.13-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "liblcms1-dev", pkgver: "1.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblcms1-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to liblcms1-dev-1.13-1ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
