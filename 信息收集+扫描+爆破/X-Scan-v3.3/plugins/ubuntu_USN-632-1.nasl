# This script was automatically generated from the 632-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33807);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "632-1");
script_summary(english:"Python vulnerabilities");
script_name(english:"USN632-1 : Python vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- idle-python2.4 
- idle-python2.5 
- python2.4 
- python2.4-dbg 
- python2.4-dev 
- python2.4-doc 
- python2.4-examples 
- python2.4-gdbm 
- python2.4-minimal 
- python2.4-tk 
- python2.5 
- python2.5-dbg 
- python2.5-dev 
- python2.5-doc 
- python2.5-examples 
- python2.5-minimal 
');
script_set_attribute(attribute:'description', value: 'It was discovered that there were new integer overflows in the imageop
module.  If an attacker were able to trick a Python application into
processing a specially crafted image, they could execute arbitrary code
with user privileges. (CVE-2008-1679)

Justin Ferguson discovered that the zlib module did not correctly
handle certain archives.  If an attacker were able to trick a Python
application into processing a specially crafted archive file, they could
execute arbitrary code with user privileges. (CVE-2008-1721)

Justin Ferguson discovered that certain string manipulations in Python
could be made to overflow.  If an attacker were able to pass a specially
crafted string through the PyString_FromStringAndSize function, they
could execute arbitrary code with user privileges. (CVE-2008-1887)

Multiple integer overflows were discovered in Python\'s core and modules
including hashlib, binascii, pickle, md5, stringobject, unicodeobject,
bufferobject, longobject, tupleobject, stropmodule, gcmodule, and
mmapmodule.
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- idle-python2.4-2.4.5-1ubuntu4.1 (Ubuntu 8.04)
- idle-python2.5-2.5.2-2ubuntu4.1 (Ubuntu 8.04)
- python2.4-2.4.5-1ubuntu4.1 (Ubuntu 8.04)
- python2.4-dbg-2.4.5-1ubuntu4.1 (Ubuntu 8.04)
- python2.4-dev-2.4.5-1ubuntu4.1 (Ubuntu 8.04)
- python2.4-doc-2.4.5-1ubuntu4.1 (Ubuntu 8.04)
- python2.4-examples-2.4.5-1ubuntu4.1 (Ubuntu 8.04)
- python2.4-gdbm-2.4.3-0ubuntu6.2 (Ubuntu 6.06)
- python2.4-minimal-2.4.5-1ubuntu4.1 (Ubuntu 8.04)
- python2.4-tk-2.4.3-0ubuntu6.2 (Ubuntu 6.06)
- python2.5-2.5.2-2u
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1679","CVE-2008-1721","CVE-2008-1887","CVE-2008-2315","CVE-2008-2316","CVE-2008-3142","CVE-2008-3143","CVE-2008-3144");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "idle-python2.4", pkgver: "2.4.5-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package idle-python2.4-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to idle-python2.4-2.4.5-1ubuntu4.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "idle-python2.5", pkgver: "2.5.2-2ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package idle-python2.5-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to idle-python2.5-2.5.2-2ubuntu4.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python2.4", pkgver: "2.4.5-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python2.4-2.4.5-1ubuntu4.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python2.4-dbg", pkgver: "2.4.5-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python2.4-dbg-2.4.5-1ubuntu4.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python2.4-dev", pkgver: "2.4.5-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python2.4-dev-2.4.5-1ubuntu4.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python2.4-doc", pkgver: "2.4.5-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python2.4-doc-2.4.5-1ubuntu4.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python2.4-examples", pkgver: "2.4.5-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-examples-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python2.4-examples-2.4.5-1ubuntu4.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-gdbm", pkgver: "2.4.3-0ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-gdbm-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-gdbm-2.4.3-0ubuntu6.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python2.4-minimal", pkgver: "2.4.5-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-minimal-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python2.4-minimal-2.4.5-1ubuntu4.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-tk", pkgver: "2.4.3-0ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-tk-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-tk-2.4.3-0ubuntu6.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python2.5", pkgver: "2.5.2-2ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.5-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python2.5-2.5.2-2ubuntu4.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python2.5-dbg", pkgver: "2.5.2-2ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.5-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python2.5-dbg-2.5.2-2ubuntu4.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python2.5-dev", pkgver: "2.5.2-2ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.5-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python2.5-dev-2.5.2-2ubuntu4.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python2.5-doc", pkgver: "2.5.2-2ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.5-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python2.5-doc-2.5.2-2ubuntu4.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python2.5-examples", pkgver: "2.5.2-2ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.5-examples-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python2.5-examples-2.5.2-2ubuntu4.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python2.5-minimal", pkgver: "2.5.2-2ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.5-minimal-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python2.5-minimal-2.5.2-2ubuntu4.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
