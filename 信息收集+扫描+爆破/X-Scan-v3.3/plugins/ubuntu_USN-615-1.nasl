# This script was automatically generated from the 615-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33124);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "615-1");
script_summary(english:"Evolution vulnerabilities");
script_name(english:"USN615-1 : Evolution vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- evolution 
- evolution-common 
- evolution-dbg 
- evolution-dev 
- evolution-plugins 
- evolution-plugins-experimental 
');
script_set_attribute(attribute:'description', value: 'Alin Rad Pop of Secunia Research discovered that Evolution did not
properly validate timezone data when processing iCalendar attachments.
If a user disabled the ITip Formatter plugin and viewed a crafted
iCalendar attachment, an attacker could cause a denial of service or
possibly execute code with user privileges. Note that the ITip
Formatter plugin is enabled by default in Ubuntu. (CVE-2008-1108)

Alin Rad Pop of Secunia Research discovered that Evolution did not
properly validate the DESCRIPTION field when processing iCalendar
attachments. If a user were tricked into accepting a crafted
iCalendar attachment and replied to it from the calendar window, an
attacker code cause a denial of service or execute code with user
privileges. (CVE-2008-1109)

Matej Cepl discovered that Evolution did not properly validate date
fields when processing iCalendar attachments. If a user disabled the
ITip Formatter plugin and viewed a crafted iCalendar attachment, an
attacker could cause a denial of service. Note that the IT
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- evolution-2.22.2-0ubuntu1.2 (Ubuntu 8.04)
- evolution-common-2.22.2-0ubuntu1.2 (Ubuntu 8.04)
- evolution-dbg-2.22.2-0ubuntu1.2 (Ubuntu 8.04)
- evolution-dev-2.22.2-0ubuntu1.2 (Ubuntu 8.04)
- evolution-plugins-2.22.2-0ubuntu1.2 (Ubuntu 8.04)
- evolution-plugins-experimental-2.22.2-0ubuntu1.2 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1108","CVE-2008-1109");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "evolution", pkgver: "2.22.2-0ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package evolution-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to evolution-2.22.2-0ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "evolution-common", pkgver: "2.22.2-0ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package evolution-common-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to evolution-common-2.22.2-0ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "evolution-dbg", pkgver: "2.22.2-0ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package evolution-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to evolution-dbg-2.22.2-0ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "evolution-dev", pkgver: "2.22.2-0ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package evolution-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to evolution-dev-2.22.2-0ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "evolution-plugins", pkgver: "2.22.2-0ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package evolution-plugins-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to evolution-plugins-2.22.2-0ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "evolution-plugins-experimental", pkgver: "2.22.2-0ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package evolution-plugins-experimental-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to evolution-plugins-experimental-2.22.2-0ubuntu1.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
