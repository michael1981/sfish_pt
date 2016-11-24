# This script was automatically generated from the 189-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20601);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "189-1");
script_summary(english:"cpio vulnerabilities");
script_name(english:"USN189-1 : cpio vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "cpio" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Imran Ghory found a race condition in the handling of output files.
While a file was unpacked with cpio, a local attacker with write
permissions to the target directory could exploit this to change the
permissions of arbitrary files of the cpio user. (CVE-2005-1111)

Imran Ghory discovered a path traversal vulnerability. Even when the
--no-absolute-filenames option was specified, cpio did not filter out
".." path components. By tricking an user into unpacking a malicious
cpio archive, this could be exploited to install files in arbitrary
paths with the privileges of the user calling cpio. (CVE-2005-1229)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- cpio-2.5-1.1ubuntu1.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-1111","CVE-2005-1229");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "cpio", pkgver: "2.5-1.1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cpio-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to cpio-2.5-1.1ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
