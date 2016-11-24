# This script was automatically generated from the dsa-1549
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32004);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1549");
 script_cve_id("CVE-2008-0314", "CVE-2008-1100", "CVE-2008-1833");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1549 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Clam anti-virus
toolkit. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2008-0314
    Damian Put discovered that a buffer overflow in the handler for
    PeSpin binaries may lead to the execution of arbitrary code.
CVE-2008-1100
    Alin Rad Pop discovered that a buffer overflow in the handler for
    Upack PE binaries may lead to the execution of arbitrary code.
CVE-2008-1833
    Damian Put and Thomas Pollet discovered that a buffer overflow in
    the handler for WWPack-compressed PE binaries may lead to the
    execution of arbitrary code.
For the stable distribution (etch) these problems have been fixed
in version 0.90.1dfsg-3etch11.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1549');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your clamav packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1549] DSA-1549-1 clamav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1549-1 clamav");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'clamav', release: '4.0', reference: '0.90.1dfsg-3etch11');
deb_check(prefix: 'clamav-base', release: '4.0', reference: '0.90.1dfsg-3etch11');
deb_check(prefix: 'clamav-daemon', release: '4.0', reference: '0.90.1dfsg-3etch11');
deb_check(prefix: 'clamav-dbg', release: '4.0', reference: '0.90.1dfsg-3etch11');
deb_check(prefix: 'clamav-docs', release: '4.0', reference: '0.90.1dfsg-3etch11');
deb_check(prefix: 'clamav-freshclam', release: '4.0', reference: '0.90.1dfsg-3etch11');
deb_check(prefix: 'clamav-milter', release: '4.0', reference: '0.90.1dfsg-3etch11');
deb_check(prefix: 'clamav-testfiles', release: '4.0', reference: '0.90.1dfsg-3etch11');
deb_check(prefix: 'libclamav-dev', release: '4.0', reference: '0.90.1dfsg-3etch11');
deb_check(prefix: 'libclamav2', release: '4.0', reference: '0.90.1dfsg-3etch11');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
