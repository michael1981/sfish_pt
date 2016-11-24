# This script was automatically generated from the dsa-1798
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38725);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1798");
 script_cve_id("CVE-2009-1194");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1798 security update');
 script_set_attribute(attribute: 'description', value:
'Will Drewry discovered that pango, a system for layout and rendering of
internationalized text, is prone to an integer overflow via long
glyphstrings. This could cause the execution of arbitrary code when
displaying crafted data through an application using the pango library.
For the oldstable distribution (etch), this problem has been fixed in
version 1.14.8-5+etch1.
For the stable distribution (lenny), this problem has been fixed in
version 1.20.5-3+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1798');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your pango1.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1798] DSA-1798-1 pango1.0");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1798-1 pango1.0");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpango1.0-0', release: '4.0', reference: '1.14.8-5+etch1');
deb_check(prefix: 'libpango1.0-0-dbg', release: '4.0', reference: '1.14.8-5+etch1');
deb_check(prefix: 'libpango1.0-common', release: '4.0', reference: '1.14.8-5+etch1');
deb_check(prefix: 'libpango1.0-dev', release: '4.0', reference: '1.14.8-5+etch1');
deb_check(prefix: 'libpango1.0-doc', release: '4.0', reference: '1.14.8-5+etch1');
deb_check(prefix: 'libpango1.0-0', release: '5.0', reference: '1.20.5-3+lenny1');
deb_check(prefix: 'libpango1.0-0-dbg', release: '5.0', reference: '1.20.5-3+lenny1');
deb_check(prefix: 'libpango1.0-common', release: '5.0', reference: '1.20.5-3+lenny1');
deb_check(prefix: 'libpango1.0-dev', release: '5.0', reference: '1.20.5-3+lenny1');
deb_check(prefix: 'libpango1.0-doc', release: '5.0', reference: '1.20.5-3+lenny1');
deb_check(prefix: 'pango1.0', release: '4.0', reference: '1.14.8-5+etch1');
deb_check(prefix: 'pango1.0', release: '5.0', reference: '1.20.5-3+lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
