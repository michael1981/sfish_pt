# This script was automatically generated from the dsa-1667
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34823);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1667");
 script_cve_id("CVE-2008-2315", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1667 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the interpreter for the
Python language. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2008-2315
    David Remahl discovered several integer overflows in the
    stringobject, unicodeobject,  bufferobject, longobject,
    tupleobject, stropmodule, gcmodule, and mmapmodule modules.
CVE-2008-3142
    Justin Ferguson discovered that incorrect memory allocation in
    the unicode_resize() function can lead to buffer overflows.
CVE-2008-3143
    Several integer overflows were discovered in various Python core
    modules.
CVE-2008-3144
    Several integer overflows were discovered in the PyOS_vsnprintf()
    function.
For the stable distribution (etch), these problems have been fixed in
version 2.4.4-3+etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1667');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your python2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1667] DSA-1667-1 python2.4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1667-1 python2.4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'idle-python2.4', release: '4.0', reference: '2.4.4-3+etch2');
deb_check(prefix: 'python2.4', release: '4.0', reference: '2.4.4-3+etch2');
deb_check(prefix: 'python2.4-dbg', release: '4.0', reference: '2.4.4-3+etch2');
deb_check(prefix: 'python2.4-dev', release: '4.0', reference: '2.4.4-3+etch2');
deb_check(prefix: 'python2.4-examples', release: '4.0', reference: '2.4.4-3+etch2');
deb_check(prefix: 'python2.4-minimal', release: '4.0', reference: '2.4.4-3+etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
