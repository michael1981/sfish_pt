# This script was automatically generated from the dsa-1351
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25859);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1351");
 script_cve_id("CVE-2007-2893");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1351 security update');
 script_set_attribute(attribute: 'description', value:
'Tavis Ormandy discovered that bochs, a highly portable IA-32 PC emulator,
is vulnerable to a buffer overflow in the emulated NE2000 network device
driver, which may lead to privilege escalation.
For the oldstable distribution (sarge) this problem has been fixed in
version 2.1.1+20041109-3sarge1.
For the stable distribution (etch) this problem has been fixed in
version 2.3-2etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1351');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your bochs packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1351] DSA-1351-1 bochs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1351-1 bochs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bochs', release: '3.1', reference: '2.1.1+20041109-3sarge1');
deb_check(prefix: 'bochs-doc', release: '3.1', reference: '2.1.1+20041109-3sarge1');
deb_check(prefix: 'bochs-sdl', release: '3.1', reference: '2.1.1+20041109-3sarge1');
deb_check(prefix: 'bochs-svga', release: '3.1', reference: '2.1.1+20041109-3sarge1');
deb_check(prefix: 'bochs-term', release: '3.1', reference: '2.1.1+20041109-3sarge1');
deb_check(prefix: 'bochs-wx', release: '3.1', reference: '2.1.1+20041109-3sarge1');
deb_check(prefix: 'bochs-x', release: '3.1', reference: '2.1.1+20041109-3sarge1');
deb_check(prefix: 'bochsbios', release: '3.1', reference: '2.1.1+20041109-3sarge1');
deb_check(prefix: 'bximage', release: '3.1', reference: '2.1.1+20041109-3sarge1');
deb_check(prefix: 'sb16ctrl-bochs', release: '3.1', reference: '2.1.1+20041109-3sarge1');
deb_check(prefix: 'bochs', release: '4.0', reference: '2.3-2etch1');
deb_check(prefix: 'bochs-doc', release: '4.0', reference: '2.3-2etch1');
deb_check(prefix: 'bochs-sdl', release: '4.0', reference: '2.3-2etch1');
deb_check(prefix: 'bochs-svga', release: '4.0', reference: '2.3-2etch1');
deb_check(prefix: 'bochs-term', release: '4.0', reference: '2.3-2etch1');
deb_check(prefix: 'bochs-wx', release: '4.0', reference: '2.3-2etch1');
deb_check(prefix: 'bochs-x', release: '4.0', reference: '2.3-2etch1');
deb_check(prefix: 'bochsbios', release: '4.0', reference: '2.3-2etch1');
deb_check(prefix: 'bximage', release: '4.0', reference: '2.3-2etch1');
deb_check(prefix: 'sb16ctrl-bochs', release: '4.0', reference: '2.3-2etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
