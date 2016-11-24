# This script was automatically generated from the 777-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38848);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "777-1");
script_summary(english:"ntp vulnerabilities");
script_name(english:"USN777-1 : ntp vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ntp 
- ntp-doc 
- ntp-refclock 
- ntp-server 
- ntp-simple 
- ntpdate 
');
script_set_attribute(attribute:'description', value: 'A stack-based buffer overflow was discovered in ntpq. If a user were
tricked into connecting to a malicious ntp server, a remote attacker could
cause a denial of service in ntpq, or possibly execute arbitrary code with
the privileges of the user invoking the program. (CVE-2009-0159)

Chris Ries discovered a stack-based overflow in ntp. If ntp was configured
to use autokey, a remote attacker could send a crafted packet to cause a
denial of service, or possible execute arbitrary code. (CVE-2009-1252)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ntp-4.2.4p4+dfsg-7ubuntu5.1 (Ubuntu 9.04)
- ntp-doc-4.2.4p4+dfsg-7ubuntu5.1 (Ubuntu 9.04)
- ntp-refclock-4.2.0a+stable-8.1ubuntu6.2 (Ubuntu 6.06)
- ntp-server-4.2.0a+stable-8.1ubuntu6.2 (Ubuntu 6.06)
- ntp-simple-4.2.0a+stable-8.1ubuntu6.2 (Ubuntu 6.06)
- ntpdate-4.2.4p4+dfsg-7ubuntu5.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-0159","CVE-2009-1252");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "ntp", pkgver: "4.2.4p4+dfsg-7ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ntp-4.2.4p4+dfsg-7ubuntu5.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ntp-doc", pkgver: "4.2.4p4+dfsg-7ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ntp-doc-4.2.4p4+dfsg-7ubuntu5.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ntp-refclock", pkgver: "4.2.0a+stable-8.1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-refclock-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ntp-refclock-4.2.0a+stable-8.1ubuntu6.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ntp-server", pkgver: "4.2.0a+stable-8.1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ntp-server-4.2.0a+stable-8.1ubuntu6.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ntp-simple", pkgver: "4.2.0a+stable-8.1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-simple-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ntp-simple-4.2.0a+stable-8.1ubuntu6.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ntpdate", pkgver: "4.2.4p4+dfsg-7ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntpdate-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ntpdate-4.2.4p4+dfsg-7ubuntu5.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
