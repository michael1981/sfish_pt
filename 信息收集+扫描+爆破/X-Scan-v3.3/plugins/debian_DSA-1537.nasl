# This script was automatically generated from the dsa-1537
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31807);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1537");
 script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1537 security update');
 script_set_attribute(attribute: 'description', value:
'Alin Rad Pop (Secunia) discovered a number of vulnerabilities in xpdf, a set
of tools for display and conversion of Portable Document Format (PDF) files.
The Common Vulnerabilities and Exposures project identifies the following
three problems:
CVE-2007-4352
    Inadequate DCT stream validation allows an attacker to corrupt
    memory and potentially execute arbitrary code by supplying a
    maliciously crafted PDF file.
CVE-2007-5392
    An integer overflow vulnerability in DCT stream handling could
    allow an attacker to overflow a heap buffer, enabling the execution
    of arbitrary code.
CVE-2007-5393
    A buffer overflow vulnerability in xpdf\'s CCITT image compression
    handlers allows overflow on the heap, allowing an attacker to
    execute arbitrary code by supplying a maliciously crafted
    CCITTFaxDecode filter.
For the stable distribution (etch), these problems have been fixed in
version 3.01-9.1+etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1537');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xpdf packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1537] DSA-1537-1 xpdf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1537-1 xpdf");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xpdf', release: '4.0', reference: '3.01-9.1+etch2');
deb_check(prefix: 'xpdf-common', release: '4.0', reference: '3.01-9.1+etch2');
deb_check(prefix: 'xpdf-reader', release: '4.0', reference: '3.01-9.1+etch2');
deb_check(prefix: 'xpdf-utils', release: '4.0', reference: '3.01-9.1+etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
