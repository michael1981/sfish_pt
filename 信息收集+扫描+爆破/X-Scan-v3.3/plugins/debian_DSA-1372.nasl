# This script was automatically generated from the dsa-1372
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(26033);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1372");
 script_cve_id("CVE-2007-4730");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1372 security update');
 script_set_attribute(attribute: 'description', value:
'Aaron Plattner discovered a buffer overflow in the Composite extension
of the X.org X server, which can lead to local privilege escalation.
The oldstable distribution (sarge) is not affected by this problem.
For the stable distribution (etch) this problem has been fixed in
version 1.1.1-21etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1372');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xorg-server packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1372] DSA-1372-1 xorg-server");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1372-1 xorg-server");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xdmx', release: '4.0', reference: '1.1.1-21etch1');
deb_check(prefix: 'xdmx-tools', release: '4.0', reference: '1.1.1-21etch1');
deb_check(prefix: 'xnest', release: '4.0', reference: '1.1.1-21etch1');
deb_check(prefix: 'xserver-xephyr', release: '4.0', reference: '1.1.1-21etch1');
deb_check(prefix: 'xserver-xorg-core', release: '4.0', reference: '1.1.1-21etch1');
deb_check(prefix: 'xserver-xorg-dev', release: '4.0', reference: '1.1.1-21etch1');
deb_check(prefix: 'xvfb', release: '4.0', reference: '1.1.1-21etch1');
deb_check(prefix: 'xorg-server', release: '4.0', reference: '1.1.1-21etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
