# This script was automatically generated from the dsa-1666
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34810);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1666");
 script_cve_id("CVE-2008-4225", "CVE-2008-4226");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1666 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the GNOME XML library.
The Common Vulnerabilities and Exposures project identifies the 
following problems:
CVE-2008-4225
    Drew Yao discovered that missing input sanitising in the
    xmlBufferResize() function may lead to an infinite loop,
    resulting in denial of service.
CVE-2008-4226
    Drew Yao discovered that an integer overflow in the
    xmlSAX2Characters() function may lead to denial of service or
    the execution of arbitrary code.
For the stable distribution (etch), these problems have been fixed in
version 2.6.27.dfsg-6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1666');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libxml2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1666] DSA-1666-1 libxml2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1666-1 libxml2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libxml2', release: '4.0', reference: '2.6.27.dfsg-6');
deb_check(prefix: 'libxml2-dbg', release: '4.0', reference: '2.6.27.dfsg-6');
deb_check(prefix: 'libxml2-dev', release: '4.0', reference: '2.6.27.dfsg-6');
deb_check(prefix: 'libxml2-doc', release: '4.0', reference: '2.6.27.dfsg-6');
deb_check(prefix: 'libxml2-utils', release: '4.0', reference: '2.6.27.dfsg-6');
deb_check(prefix: 'python-libxml2', release: '4.0', reference: '2.6.27.dfsg-6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
