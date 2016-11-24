# This script was automatically generated from the dsa-890
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22756);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "890");
 script_cve_id("CVE-2005-2974", "CVE-2005-3350");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-890 security update');
 script_set_attribute(attribute: 'description', value:
'Chris Evans discovered several security related problems in libungif4,
a shared library for GIF images.  The Common Vulnerabilities and
Exposures project identifies the following vulnerabilities:
CVE-2005-2974
    Null pointer dereference, that could cause a denial of service.
CVE-2005-3350
    Out of bounds memory access that could cause a denial of service
    or the execution of arbitrary code.
For the old stable distribution (woody) these problems have been fixed in
version 4.1.0b1-2woody1.
For the stable distribution (sarge) these problems have been fixed in
version 4.1.3-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-890');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libungif4 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA890] DSA-890-1 libungif4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-890-1 libungif4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libungif-bin', release: '3.0', reference: '4.1.0b1-2woody1');
deb_check(prefix: 'libungif4-dev', release: '3.0', reference: '4.1.0b1-2woody1');
deb_check(prefix: 'libungif4g', release: '3.0', reference: '4.1.0b1-2woody1');
deb_check(prefix: 'libungif-bin', release: '3.1', reference: '4.1.3-2sarge1');
deb_check(prefix: 'libungif4-dev', release: '3.1', reference: '4.1.3-2sarge1');
deb_check(prefix: 'libungif4g', release: '3.1', reference: '4.1.3-2sarge1');
deb_check(prefix: 'libungif4', release: '3.1', reference: '4.1.3-2sarge1');
deb_check(prefix: 'libungif4', release: '3.0', reference: '4.1.0b1-2woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
