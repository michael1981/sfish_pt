# This script was automatically generated from the dsa-1618
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33738);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1618");
 script_cve_id("CVE-2008-2376", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1618 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the interpreter for
the Ruby language, which may lead to denial of service or the
execution of arbitrary code. The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2008-2662
    Drew Yao discovered that multiple integer overflows in the string
    processing code may lead to denial of service and potentially the
    execution of arbitrary code.
CVE-2008-2663
    Drew Yao discovered that multiple integer overflows in the string
    processing code may lead to denial of service and potentially the
    execution of arbitrary code.
CVE-2008-2664
    Drew Yao discovered that a programming error in the string
    processing code may lead to denial of service and potentially the
    execution of arbitrary code.
CVE-2008-2725
    Drew Yao discovered that an integer overflow in the array handling
    code may lead to denial of service and potentially the execution
    of arbitrary code.
CVE-2008-2726
    Drew Yao discovered that an integer overflow in the array handling
    code may lead to denial of service and potentially the execution
    of arbitrary code.
CVE-2008-2376
    It was discovered that an integer overflow in the array handling
    code may lead to denial of service and potentially the execution
    of arbitrary code.
For the stable distribution (etch), these problems have been fixed in
version 1.9.0+20060609-1etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1618');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ruby1.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1618] DSA-1618-1 ruby1.9");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1618-1 ruby1.9");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'irb1.9', release: '4.0', reference: '1.9.0+20060609-1etch2');
deb_check(prefix: 'libdbm-ruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch2');
deb_check(prefix: 'libgdbm-ruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch2');
deb_check(prefix: 'libopenssl-ruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch2');
deb_check(prefix: 'libreadline-ruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch2');
deb_check(prefix: 'libruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch2');
deb_check(prefix: 'libruby1.9-dbg', release: '4.0', reference: '1.9.0+20060609-1etch2');
deb_check(prefix: 'libtcltk-ruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch2');
deb_check(prefix: 'rdoc1.9', release: '4.0', reference: '1.9.0+20060609-1etch2');
deb_check(prefix: 'ri1.9', release: '4.0', reference: '1.9.0+20060609-1etch2');
deb_check(prefix: 'ruby1.9', release: '4.0', reference: '1.9.0+20060609-1etch2');
deb_check(prefix: 'ruby1.9-dev', release: '4.0', reference: '1.9.0+20060609-1etch2');
deb_check(prefix: 'ruby1.9-elisp', release: '4.0', reference: '1.9.0+20060609-1etch2');
deb_check(prefix: 'ruby1.9-examples', release: '4.0', reference: '1.9.0+20060609-1etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
