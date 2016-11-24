# This script was automatically generated from the dsa-1684
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35077);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1684");
 script_cve_id("CVE-2008-5316", "CVE-2008-5317");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1684 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been found in lcms, a library and set of
commandline utilities for image color management.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
CVE-2008-5316
    Inadequate enforcement of fixed-length buffer limits allows an
    attacker to overflow a buffer on the stack, potentially enabling
    the execution of arbitrary code when a maliciously-crafted
    image is opened.
    An integer sign error in reading image gamma data could allow an
    attacker to cause an under-sized buffer to be allocated for
    subsequent image data, with unknown consequences potentially
    including the execution of arbitrary code if a maliciously-crafted
    image is opened.
For the stable distribution (etch), these problems have been fixed in
version 1.15-1.1+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1684');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lcms packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1684] DSA-1684-1 lcms");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1684-1 lcms");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'liblcms-utils', release: '4.0', reference: '1.15-1.1+etch1');
deb_check(prefix: 'liblcms1', release: '4.0', reference: '1.15-1.1+etch1');
deb_check(prefix: 'liblcms1-dev', release: '4.0', reference: '1.15-1.1+etch1');
deb_check(prefix: 'lcms', release: '4.0', reference: '1.15-1.1+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
