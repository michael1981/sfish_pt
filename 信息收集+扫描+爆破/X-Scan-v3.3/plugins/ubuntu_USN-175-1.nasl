# This script was automatically generated from the 175-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20585);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "175-1");
script_summary(english:"ntp vulnerability");
script_name(english:"USN175-1 : ntp vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ntp 
- ntp-doc 
- ntp-refclock 
- ntp-server 
- ntp-simple 
- ntpdate 
');
script_set_attribute(attribute:'description', value: 'Thomas Biege discovered a flaw in the privilege dropping of the NTP
server. When ntpd was configured to drop root privileges, and the
group to run under was specified as a name (as opposed to a numeric
group ID), ntpd changed to the wrong group. Depending on the actual
group it changed to, this could either cause non-minimal privileges,
or a malfunctioning ntp server if the group does not have the
privileges that ntpd actually needs.

On Ubuntu 4.10, ntpd does not use privilege dropping by default, so
you are only affected if you manually activated it. In Ubuntu 5.04,
privilege dropping is used by default, but this bug is already fixed.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ntp-4.2.0a-10ubuntu2.1 (Ubuntu 4.10)
- ntp-doc-4.2.0a-10ubuntu2.1 (Ubuntu 4.10)
- ntp-refclock-4.2.0a-10ubuntu2.1 (Ubuntu 4.10)
- ntp-server-4.2.0a-10ubuntu2.1 (Ubuntu 4.10)
- ntp-simple-4.2.0a-10ubuntu2.1 (Ubuntu 4.10)
- ntpdate-4.2.0a-10ubuntu2.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-2496");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "ntp", pkgver: "4.2.0a-10ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ntp-4.2.0a-10ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "ntp-doc", pkgver: "4.2.0a-10ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ntp-doc-4.2.0a-10ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "ntp-refclock", pkgver: "4.2.0a-10ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-refclock-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ntp-refclock-4.2.0a-10ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "ntp-server", pkgver: "4.2.0a-10ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-server-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ntp-server-4.2.0a-10ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "ntp-simple", pkgver: "4.2.0a-10ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntp-simple-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ntp-simple-4.2.0a-10ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "ntpdate", pkgver: "4.2.0a-10ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ntpdate-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ntpdate-4.2.0a-10ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
