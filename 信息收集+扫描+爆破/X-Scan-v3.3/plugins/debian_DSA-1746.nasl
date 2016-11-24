# This script was automatically generated from the dsa-1746
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35968);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1746");
 script_cve_id("CVE-2009-0583", "CVE-2009-0584");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1746 security update');
 script_set_attribute(attribute: 'description', value:
'Two security issues have been discovered in ghostscript, the GPL
Ghostscript PostScript/PDF interpreter. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2009-0583
Jan Lieskovsky discovered multiple integer overflows in the ICC library,
which allow the execution of arbitrary code via crafted ICC profiles in
PostScript files with embedded images.
CVE-2009-0584
Jan Lieskovsky discovered insufficient upper-bounds checks on certain
variable sizes in the ICC library, which allow the execution of
arbitrary code via crafted ICC profiles in PostScript files with
embedded images.
For the stable distribution (lenny), these problems have been fixed in
version 8.62.dfsg.1-3.2lenny1.
For the oldstable distribution (etch), these problems have been fixed
in version 8.54.dfsg.1-5etch2. Please note that the package in oldstable
is called gs-gpl.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1746');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ghostscript/gs-gpl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1746] DSA-1746-1 ghostscript");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1746-1 ghostscript");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gs', release: '4.0', reference: '8.54.dfsg.1-5etch2');
deb_check(prefix: 'gs-gpl', release: '4.0', reference: '8.54.dfsg.1-5etch2');
deb_check(prefix: 'ghostscript', release: '5.0', reference: '8.62.dfsg.1-3.2lenny1');
deb_check(prefix: 'ghostscript-doc', release: '5.0', reference: '8.62.dfsg.1-3.2lenny1');
deb_check(prefix: 'ghostscript-x', release: '5.0', reference: '8.62.dfsg.1-3.2lenny1');
deb_check(prefix: 'gs', release: '5.0', reference: '8.62.dfsg.1-3.2lenny1');
deb_check(prefix: 'gs-aladdin', release: '5.0', reference: '8.62.dfsg.1-3.2lenny1');
deb_check(prefix: 'gs-common', release: '5.0', reference: '8.62.dfsg.1-3.2lenny1');
deb_check(prefix: 'gs-esp', release: '5.0', reference: '8.62.dfsg.1-3.2lenny1');
deb_check(prefix: 'gs-gpl', release: '5.0', reference: '8.62.dfsg.1-3.2lenny1');
deb_check(prefix: 'libgs-dev', release: '5.0', reference: '8.62.dfsg.1-3.2lenny1');
deb_check(prefix: 'libgs8', release: '5.0', reference: '8.62.dfsg.1-3.2lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
