# This script was automatically generated from the dsa-887
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22753);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "887");
 script_cve_id("CVE-2005-3239", "CVE-2005-3303", "CVE-2005-3500", "CVE-2005-3501");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-887 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Clam AntiVirus, the
antivirus scanner for Unix, designed for integration with mail servers
to perform attachment scanning.  The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2005-3239
    The OLE2 unpacker allows remote attackers to cause a segmentation
    fault via a DOC file with an invalid property tree, which triggers
    an infinite recursion.
CVE-2005-3303
    A specially crafted executable compressed with FSG 1.33 could
    cause the extractor to write beyond buffer boundaries, allowing an
    attacker to execute arbitrary code.
CVE-2005-3500
    A specially crafted CAB file could cause ClamAV to be locked in an
    infinite loop and use all available processor resources, resulting
    in a denial of service.
CVE-2005-3501
    A specially crafted CAB file could cause ClamAV to be locked in an
    infinite loop and use all available processor resources, resulting
    in a denial of service.
The old stable distribution (woody) does not contain clamav packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.84-2.sarge.6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-887');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your clamav packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA887] DSA-887-1 clamav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-887-1 clamav");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'clamav', release: '3.1', reference: '0.84-2.sarge.6');
deb_check(prefix: 'clamav-base', release: '3.1', reference: '0.84-2.sarge.6');
deb_check(prefix: 'clamav-daemon', release: '3.1', reference: '0.84-2.sarge.6');
deb_check(prefix: 'clamav-docs', release: '3.1', reference: '0.84-2.sarge.6');
deb_check(prefix: 'clamav-freshclam', release: '3.1', reference: '0.84-2.sarge.6');
deb_check(prefix: 'clamav-milter', release: '3.1', reference: '0.84-2.sarge.6');
deb_check(prefix: 'clamav-testfiles', release: '3.1', reference: '0.84-2.sarge.6');
deb_check(prefix: 'libclamav-dev', release: '3.1', reference: '0.84-2.sarge.6');
deb_check(prefix: 'libclamav1', release: '3.1', reference: '0.84-2.sarge.6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
