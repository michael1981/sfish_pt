# This script was automatically generated from the dsa-1551
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32006);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1551");
 script_cve_id("CVE-2007-2052", "CVE-2007-4965", "CVE-2008-1679", "CVE-2008-1721", "CVE-2008-1887");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1551 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the interpreter for the
Python language. The Common Vulnerabilities and Exposures project identifies
the following problems:
CVE-2007-2052
    Piotr Engelking discovered that the strxfrm() function of the locale
    module miscalculates the length of an internal buffer, which may
    result in a minor information disclosure.
CVE-2007-4965
    It was discovered that several integer overflows in the imageop
    module may lead to the execution of arbitrary code, if a user is
    tricked into processing malformed images. This issue is also
    tracked as CVE-2008-1679 due to an initially incomplete patch.
CVE-2008-1721
    Justin Ferguson discovered that a buffer overflow in the zlib
    module may lead to the execution of arbitrary code.
CVE-2008-1887
    Justin Ferguson discovered that insufficient input validation in
    PyString_FromStringAndSize() may lead to the execution of arbitrary
    code.
For the stable distribution (etch), these problems have been fixed in
version 2.4.4-3+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1551');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your python2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1551] DSA-1551-1 python2.4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1551-1 python2.4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'idle-python2.4', release: '4.0', reference: '2.4.4-3+etch1');
deb_check(prefix: 'python2.4', release: '4.0', reference: '2.4.4-3+etch1');
deb_check(prefix: 'python2.4-dbg', release: '4.0', reference: '2.4.4-3+etch1');
deb_check(prefix: 'python2.4-dev', release: '4.0', reference: '2.4.4-3+etch1');
deb_check(prefix: 'python2.4-examples', release: '4.0', reference: '2.4.4-3+etch1');
deb_check(prefix: 'python2.4-minimal', release: '4.0', reference: '2.4.4-3+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
