# This script was automatically generated from the 705-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37876);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "705-1");
script_summary(english:"ntp vulnerability");
script_name(english:"USN705-1 : ntp vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ntp 
- ntp-doc 
- ntp-refclock 
- ntp-server 
- ntp-simple 
- ntpdate 
');
script_set_attribute(attribute:'description', value: 'It was discovered that NTP did not properly perform signature verification.
A remote attacker could exploit this to bypass certificate validation via
a malformed SSL/TLS signature.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ntp-4.2.4p4+dfsg-6ubuntu2.2 (Ubuntu 8.10)
- ntp-doc-4.2.4p4+dfsg-6ubuntu2.2 (Ubuntu 8.10)
- ntp-refclock-4.2.0a+stable-8.1ubuntu6.1 (Ubuntu 6.06)
- ntp-server-4.2.0a+stable-8.1ubuntu6.1 (Ubuntu 6.06)
- ntp-simple-4.2.0a+stable-8.1ubuntu6.1 (Ubuntu 6.06)
- ntpdate-4.2.4p4+dfsg-6ubuntu2.2 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2009-0021");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "ntp", pkgver: "4.2.4p4+dfsg-6ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ntp-4.2.4p4+dfsg-6ubuntu2.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ntp-doc", pkgver: "4.2.4p4+dfsg-6ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ntp-doc-4.2.4p4+dfsg-6ubuntu2.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ntp-refclock", pkgver: "4.2.0a+stable-8.1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-refclock-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ntp-refclock-4.2.0a+stable-8.1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ntp-server", pkgver: "4.2.0a+stable-8.1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ntp-server-4.2.0a+stable-8.1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ntp-simple", pkgver: "4.2.0a+stable-8.1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-simple-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ntp-simple-4.2.0a+stable-8.1ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ntpdate", pkgver: "4.2.4p4+dfsg-6ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntpdate-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ntpdate-4.2.4p4+dfsg-6ubuntu2.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
