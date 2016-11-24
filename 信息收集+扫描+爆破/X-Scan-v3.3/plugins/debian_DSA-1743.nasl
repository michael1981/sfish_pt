# This script was automatically generated from the dsa-1743
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35932);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1743");
 script_cve_id("CVE-2007-5137", "CVE-2007-5378");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1743 security update');
 script_set_attribute(attribute: 'description', value:
'Two buffer overflows have been found in the GIF image parsing code of
Tk, a cross-platform graphical toolkit, which could lead to the execution
of arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2007-5137
It was discovered that libtk-img is prone to a buffer overflow via
specially crafted multi-frame interlaced GIF files.
CVE-2007-5378
It was discovered that libtk-img is prone to a buffer overflow via
specially crafted GIF files with certain subimage sizes.
For the stable distribution (lenny), these problems have been fixed in
version 1.3-release-7+lenny1.
For the oldstable distribution (etch), these problems have been fixed in
version 1.3-15etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1743');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libtk-img packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1743] DSA-1743-1 libtk-img");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1743-1 libtk-img");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtk-img', release: '4.0', reference: '1.3-15etch3');
deb_check(prefix: 'libtk-img', release: '5.0', reference: '1.3-release-7+lenny1');
deb_check(prefix: 'libtk-img-dev', release: '5.0', reference: '1.3-release-7+lenny1');
deb_check(prefix: 'libtk-img-doc', release: '5.0', reference: '1.3-release-7+lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
