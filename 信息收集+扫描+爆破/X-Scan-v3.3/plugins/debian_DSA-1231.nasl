# This script was automatically generated from the dsa-1231
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23792);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1231");
 script_cve_id("CVE-2006-6169", "CVE-2006-6235");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1231 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the GNU privacy guard,
a free PGP replacement, which may lead to the execution of arbitrary code.
The Common Vulnerabilities and Exposures project identifies the following
problems:
CVE-2006-6169
    Werner Koch discovered that a buffer overflow in a sanitising function
    may lead to execution of arbitrary code when running gnupg
    interactively.
CVE-2006-6235
    Tavis Ormandy discovered that parsing a carefully crafted OpenPGP
    packet may lead to the execution of arbitrary code, as a function
    pointer of an internal structure may be controlled through the
    decryption routines.
For the stable distribution (sarge) these problems have been fixed in
version 1.4.1-1.sarge6.
For the upcoming stable distribution (etch) these problems have been
fixed in version 1.4.6-1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1231');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gnupg packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1231] DSA-1231-1 gnupg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1231-1 gnupg");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnupg', release: '3.1', reference: '1.4.1-1.sarge6');
deb_check(prefix: 'gnupg', release: '4.0', reference: '1.4.6-1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
