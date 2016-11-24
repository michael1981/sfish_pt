# This script was automatically generated from the dsa-1635
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34163);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1635");
 script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1635 security update');
 script_set_attribute(attribute: 'description', value:
'Several local vulnerabilities have been discovered in freetype,
a FreeType 2 font engine, which could allow the execution of arbitrary
code.
The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2008-1806
    An integer overflow allows context-dependent attackers to execute
    arbitrary code via a crafted set of values within the Private
    dictionary table in a Printer Font Binary (PFB) file.
CVE-2008-1807
    The handling of an invalid <q>number of axes</q> field in the PFB file could
    trigger the freeing of arbitrary memory locations, leading to 
    memory corruption.
CVE-2008-1808
    Multiple off-by-one errors allowed the execution of arbitrary code
    via malformed tables in PFB files, or invalid SHC instructions in
    TTF files.
For the stable distribution (etch), these problems have been fixed in version
2.2.1-5+etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1635');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your freetype package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1635] DSA-1635-1 freetype");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1635-1 freetype");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'freetype2-demos', release: '4.0', reference: '2.2.1-5+etch3');
deb_check(prefix: 'libfreetype6', release: '4.0', reference: '2.2.1-5+etch3');
deb_check(prefix: 'libfreetype6-dev', release: '4.0', reference: '2.2.1-5+etch3');
deb_check(prefix: 'freetype', release: '4.0', reference: '2.2.1-5+etch3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
