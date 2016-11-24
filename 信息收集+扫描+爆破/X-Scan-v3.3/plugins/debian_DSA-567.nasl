# This script was automatically generated from the dsa-567
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15665);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "567");
 script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886");
 script_bugtraq_id(11406);
 script_xref(name: "CERT", value: "555304");
 script_xref(name: "CERT", value: "687568");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-567 security update');
 script_set_attribute(attribute: 'description', value:
'Several problems have been discovered in libtiff, the Tag Image File
Format library for processing TIFF graphics files.  An attacker could
prepare a specially crafted TIFF graphic that would cause the client
to execute arbitrary code or crash.  The Common Vulnerabilities and
Exposures Project has identified the following problems:
    Chris Evans discovered several problems in the RLE (run length
    encoding) decoders that could lead to arbitrary code execution.
    Matthias Clasen discovered a division by zero through an integer
    overflow.
    Dmitry V. Levin discovered several integer overflows that caused
    malloc issues which can result to either plain crash or memory
    corruption.
For the stable distribution (woody) these problems have been fixed in
version 3.5.5-6woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-567');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libtiff package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA567] DSA-567-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-567-1 tiff");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtiff-tools', release: '3.0', reference: '3.5.5-6woody1');
deb_check(prefix: 'libtiff3g', release: '3.0', reference: '3.5.5-6woody1');
deb_check(prefix: 'libtiff3g-dev', release: '3.0', reference: '3.5.5-6woody1');
deb_check(prefix: 'tiff', release: '3.0', reference: '3.5.5-6woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
