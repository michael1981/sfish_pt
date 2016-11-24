# This script was automatically generated from the dsa-1206
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23655);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1206");
 script_cve_id("CVE-2005-3353", "CVE-2006-3017", "CVE-2006-4482", "CVE-2006-5465");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1206 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in PHP, a
server-side, HTML-embedded scripting language, which may lead to the
execution of arbitrary code. The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2005-3353
    Tim Starling discovered that missing input sanitising in the EXIF
    module could lead to denial of service.
CVE-2006-3017
    Stefan Esser discovered a security-critical programming error in the
    hashtable implementation of the internal Zend engine.
CVE-2006-4482
    It was discovered that str_repeat() and wordwrap() functions perform
    insufficient checks for buffer boundaries on 64 bit systems, which
    might lead to the execution of arbitrary code.
CVE-2006-5465
    Stefan Esser discovered a buffer overflow in the htmlspecialchars()
    and htmlentities(), which might lead to the execution of arbitrary
    code.
For the stable distribution (sarge) these problems have been fixed in
version 4:4.3.10-18. Builds for hppa and m68k will be provided later
once they are available.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1206');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your php4 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1206] DSA-1206-1 php4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1206-1 php4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-php4', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'libapache2-mod-php4', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-cgi', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-cli', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-common', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-curl', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-dev', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-domxml', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-gd', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-imap', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-ldap', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-mcal', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-mhash', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-mysql', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-odbc', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-pear', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-recode', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-snmp', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-sybase', release: '3.1', reference: '4.3.10-18');
deb_check(prefix: 'php4-xslt', release: '3.1', reference: '4.3.10-18');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
