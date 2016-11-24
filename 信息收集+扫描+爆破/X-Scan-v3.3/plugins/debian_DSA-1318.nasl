# This script was automatically generated from the dsa-1318
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25584);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1318");
 script_cve_id("CVE-2005-2370", "CVE-2005-2448", "CVE-2007-1663", "CVE-2007-1664", "CVE-2007-1665");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1318 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in ekg, a console
Gadu Gadu client. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2005-2370
    It was discovered that memory alignment errors may allow remote
    attackers to cause a denial of service on certain architectures
    such as sparc. This only affects Debian Sarge.
CVE-2005-2448
    It was discovered that several endianess errors may allow remote
    attackers to cause a denial of service. This only affects 
    Debian Sarge.
CVE-2007-1663
    It was discovered that a memory leak in handling image messages may
    lead to denial of service. This only affects Debian Etch.
CVE-2007-1664
    It was discovered that a null pointer deference in the token OCR code
    may lead to denial of service. This only affects Debian Etch.
CVE-2007-1665
    It was discovered that a memory leak in the token OCR code may lead
    to denial of service. This only affects Debian Etch.
For the oldstable distribution (sarge) these problems have been fixed in
version 1.5+20050411-7. This updates lacks updated packages for the m68k
architecture. They will be provided later.
For the stable distribution (etch) these problems have been fixed
in version 1:1.7~rc2-1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1318');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ekg packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1318] DSA-1318-1 ekg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1318-1 ekg");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ekg', release: '3.1', reference: '1.5+20050411-7');
deb_check(prefix: 'libgadu-dev', release: '3.1', reference: '1.5+20050411-7');
deb_check(prefix: 'libgadu3', release: '3.1', reference: '1.5+20050411-7');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
