# This script was automatically generated from the dsa-1589
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32457);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1589");
 script_cve_id("CVE-2008-1767");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1589 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that libxslt, an XSLT processing runtime library,
could be coerced into executing arbitrary code via a buffer overflow
when an XSL style sheet file with a long XSLT "transformation match"
condition triggered a large number of steps.
For the stable distribution (etch), this problem has been fixed in version
1.1.19-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1589');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libxslt package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1589] DSA-1589-1 libxslt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1589-1 libxslt");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libxslt1-dbg', release: '4.0', reference: '1.1.19-2');
deb_check(prefix: 'libxslt1-dev', release: '4.0', reference: '1.1.19-2');
deb_check(prefix: 'libxslt1.1', release: '4.0', reference: '1.1.19-2');
deb_check(prefix: 'python-libxslt1', release: '4.0', reference: '1.1.19-2');
deb_check(prefix: 'xsltproc', release: '4.0', reference: '1.1.19-2');
deb_check(prefix: 'libxslt', release: '4.0', reference: '1.1.19-2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
