# This script was automatically generated from the 425-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28018);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "425-1");
script_summary(english:"slocate vulnerability");
script_name(english:"USN425-1 : slocate vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "slocate" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'A flaw was discovered in the permission checking code of slocate.  When 
reporting matching files, locate would not correctly respect the parent 
directory\'s "read" bits.  This could result in filenames being displayed 
when the file owner had expected them to remain hidden from other system 
users.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- slocate-3.1-1ubuntu0.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2007-0227");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "slocate", pkgver: "3.1-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package slocate-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to slocate-3.1-1ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
