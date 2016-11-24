# This script was automatically generated from the dsa-1586
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32435);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1586");
 script_cve_id("CVE-2008-1482", "CVE-2008-1686", "CVE-2008-1878");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1586 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple vulnerabilities have been discovered in xine-lib, a library
which supplies most of the application functionality of the xine
multimedia player.  The Common Vulnerabilities and Exposures project
identifies the following three problems:
CVE-2008-1482
    Integer overflow vulnerabilities exist in xine\'s FLV, QuickTime,
    RealMedia, MVE and CAK demuxers, as well as the EBML parser used
    by the Matroska demuxer.  These weaknesses allow an attacker to
    overflow heap buffers and potentially execute arbitrary code by
    supplying a maliciously crafted file of those types.
CVE-2008-1686
    Insufficient input validation in the Speex implementation used
    by this version of xine enables an invalid array access and the
    execution of arbitrary code by supplying a maliciously crafted
    Speex file.
CVE-2008-1878
    Inadequate bounds checking in the NES Sound Format (NSF) demuxer
    enables a stack buffer overflow and the execution of arbitrary
    code through a maliciously crafted NSF file.
For the stable distribution (etch), these problems have been fixed in
version 1.1.2+dfsg-7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1586');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xine-lib packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1586] DSA-1586-1 xine-lib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1586-1 xine-lib");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libxine-dev', release: '4.0', reference: '1.1.2+dfsg-7');
deb_check(prefix: 'libxine1', release: '4.0', reference: '1.1.2+dfsg-7');
deb_check(prefix: 'libxine1-dbg', release: '4.0', reference: '1.1.2+dfsg-7');
deb_check(prefix: 'xine-lib', release: '4.0', reference: '1.1.2+dfsg-7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
