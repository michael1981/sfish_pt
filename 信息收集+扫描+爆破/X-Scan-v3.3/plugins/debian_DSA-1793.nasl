# This script was automatically generated from the dsa-1793
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38703);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1793");
 script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1793 security update');
 script_set_attribute(attribute: 'description', value:
'kpdf, a Portable Document Format (PDF) viewer for KDE, is based on the
xpdf program and thus suffers from similar flaws to those described in
DSA-1790.
The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2009-0146
    Multiple buffer overflows in the JBIG2 decoder in kpdf allow
    remote attackers to cause a denial of service (crash) via a
    crafted PDF file, related to (1) JBIG2SymbolDict::setBitmap and
    (2) JBIG2Stream::readSymbolDictSeg.
CVE-2009-0147
    Multiple integer overflows in the JBIG2 decoder in kpdf allow
    remote attackers to cause a denial of service (crash) via a
    crafted PDF file, related to (1) JBIG2Stream::readSymbolDictSeg,
    (2) JBIG2Stream::readSymbolDictSeg, and (3)
    JBIG2Stream::readGenericBitmap.
CVE-2009-0165
    Integer overflow in the JBIG2 decoder in kpdf has unspecified
    impact related to "g*allocn."
CVE-2009-0166
    The JBIG2 decoder in kpdf allows remote attackers to cause a
    denial of service (crash) via a crafted PDF file that triggers a
    free of uninitialized memory.
CVE-2009-0799
    The JBIG2 decoder in kpdf allows remote attackers to cause a
    denial of service (crash) via a crafted PDF file that triggers an
    out-of-bounds read.
CVE-2009-0800
    Multiple "input validation flaws" in the JBIG2 decoder in kpdf
    allow remote attackers to execute arbitrary code via a crafted PDF
    file.
CVE-2009-1179
    Integer overflow in the JBIG2 decoder in kpdf allows remote
    attackers to execute arbitrary code via a crafted PDF file.
CVE-2009-1180
    The JBIG2 decoder in kpdf allows remote attackers to execute
    arbitrary code via a crafted PDF file that triggers a free of
    invalid data.
CVE-2009-1181
    The JBIG2 decoder in kpdf allows remote attackers to cause a
    denial of service (crash) via a crafted PDF file that triggers a
    NULL pointer dereference.
CVE-2009-1182
    Multiple buffer overflows in the JBIG2 MMR decoder in kpdf allow
    remote attackers to execute arbitrary code via a crafted PDF file.
CVE-2009-1183
    The JBIG2 MMR decoder in kpdf allows remote attackers to cause a
    denial of service (infinite loop and hang) via a crafted PDF file.
The old stable distribution (etch), these problems have been fixed in version
3.5.5-3etch3.
For the stable distribution (lenny), these problems have been fixed in version
3.5.9-3+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1793');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kdegraphics packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1793] DSA-1793-1 kdegraphics");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1793-1 kdegraphics");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kamera', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kcoloredit', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kdegraphics', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kdegraphics-dbg', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kdegraphics-dev', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kdegraphics-doc-html', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kdegraphics-kfile-plugins', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kdvi', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kfax', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kfaxview', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kgamma', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kghostview', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kiconedit', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kmrml', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kolourpaint', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kooka', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kpdf', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kpovmodeler', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kruler', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'ksnapshot', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'ksvg', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kuickshow', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kview', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kviewshell', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'libkscan-dev', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'libkscan1', release: '4.0', reference: '3.5.5-3etch3');
deb_check(prefix: 'kamera', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kcoloredit', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kdegraphics', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kdegraphics-dbg', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kdegraphics-dev', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kdegraphics-doc-html', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kdegraphics-kfile-plugins', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kdvi', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kfax', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kfaxview', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kgamma', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kghostview', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kiconedit', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kmrml', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kolourpaint', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kooka', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kpdf', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kpovmodeler', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kruler', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'ksnapshot', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'ksvg', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kuickshow', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kview', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'kviewshell', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'libkscan-dev', release: '5.0', reference: '3.5.9-3+lenny1');
deb_check(prefix: 'libkscan1', release: '5.0', reference: '3.5.9-3+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
