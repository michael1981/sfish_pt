# This script was automatically generated from the dsa-1796
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38704);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1796");
 script_cve_id("CVE-2009-1364");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1796 security update');
 script_set_attribute(attribute: 'description', value:
'Tavis Ormandy discovered that the embedded GD library copy in libwmf,
a library to parse windows metafiles (WMF), makes use of a pointer
after it was already freed.  An attacker using a crafted WMF file can
cause a denial of service or possibly the execute arbitrary code via
applications using this library.
For the oldstable distribution (etch), this problem has been fixed in
version 0.2.8.4-2+etch1.
For the stable distribution (lenny), this problem has been fixed in
version 0.2.8.4-6+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1796');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libwmf packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1796] DSA-1796-1 libwmf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1796-1 libwmf");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libwmf-bin', release: '4.0', reference: '0.2.8.4-2+etch1');
deb_check(prefix: 'libwmf-dev', release: '4.0', reference: '0.2.8.4-2+etch1');
deb_check(prefix: 'libwmf-doc', release: '4.0', reference: '0.2.8.4-2+etch1');
deb_check(prefix: 'libwmf0.2-7', release: '4.0', reference: '0.2.8.4-2+etch1');
deb_check(prefix: 'libwmf-bin', release: '5.0', reference: '0.2.8.4-6+lenny1');
deb_check(prefix: 'libwmf-dev', release: '5.0', reference: '0.2.8.4-6+lenny1');
deb_check(prefix: 'libwmf-doc', release: '5.0', reference: '0.2.8.4-6+lenny1');
deb_check(prefix: 'libwmf0.2-7', release: '5.0', reference: '0.2.8.4-6+lenny1');
deb_check(prefix: 'libwmf', release: '4.0', reference: '0.2.8.4-2+etch1');
deb_check(prefix: 'libwmf', release: '5.0', reference: '0.2.8.4-6+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
