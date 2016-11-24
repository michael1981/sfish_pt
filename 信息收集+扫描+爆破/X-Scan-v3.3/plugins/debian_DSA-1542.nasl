# This script was automatically generated from the dsa-1542
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31948);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1542");
 script_cve_id("CVE-2007-5503");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1542 security update');
 script_set_attribute(attribute: 'description', value:
'Peter Valchev (Google Security) discovered a series of integer
overflow weaknesses in Cairo, a vector graphics rendering library used
by many other applications.  If an application uses cairo to render a
maliciously crafted PNG image, the vulnerability allows the execution
of arbitrary code.
For the stable distribution (etch), these problems have been fixed in
version 1.2.4-4.1+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1542');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libcairo packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1542] DSA-1542-1 libcairo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1542-1 libcairo");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libcairo-directfb2', release: '4.0', reference: '1.2.4-4.1+etch1');
deb_check(prefix: 'libcairo-directfb2-dev', release: '4.0', reference: '1.2.4-4.1+etch1');
deb_check(prefix: 'libcairo2', release: '4.0', reference: '1.2.4-4.1+etch1');
deb_check(prefix: 'libcairo2-dev', release: '4.0', reference: '1.2.4-4.1+etch1');
deb_check(prefix: 'libcairo2-doc', release: '4.0', reference: '1.2.4-4.1+etch1');
deb_check(prefix: 'libcairo', release: '4.0', reference: '1.2.4-4.1+etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
