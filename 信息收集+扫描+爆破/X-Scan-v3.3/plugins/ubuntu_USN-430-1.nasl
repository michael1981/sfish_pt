# This script was automatically generated from the 430-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28024);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "430-1");
script_summary(english:"mod_python vulnerability");
script_name(english:"USN430-1 : mod_python vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libapache2-mod-python 
- libapache2-mod-python-doc 
- libapache2-mod-python2.3 
- libapache2-mod-python2.4 
');
script_set_attribute(attribute:'description', value: 'Miles Egan discovered that mod_python, when used in output filter mode, 
did not handle output larger than 16384 bytes, and would display freed 
memory, possibly disclosing private data.  Thanks to Jim Garrison of the 
Software Freedom Law Center for identifying the original bug as a 
security vulnerability.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libapache2-mod-python-3.1.4-0ubuntu1.1 (Ubuntu 6.06)
- libapache2-mod-python-doc-3.1.4-0ubuntu1.1 (Ubuntu 6.06)
- libapache2-mod-python2.3-3.1.3-3ubuntu1.1 (Ubuntu 5.10)
- libapache2-mod-python2.4-3.1.4-0ubuntu1.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2004-2680");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libapache2-mod-python", pkgver: "3.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-python-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libapache2-mod-python-3.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libapache2-mod-python-doc", pkgver: "3.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-python-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libapache2-mod-python-doc-3.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libapache2-mod-python2.3", pkgver: "3.1.3-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-python2.3-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libapache2-mod-python2.3-3.1.3-3ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libapache2-mod-python2.4", pkgver: "3.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-python2.4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libapache2-mod-python2.4-3.1.4-0ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
