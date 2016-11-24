# This script was automatically generated from the dsa-1371
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(26032);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1371");
 script_cve_id("CVE-2007-2024", "CVE-2007-2025", "CVE-2007-3193");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1371 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in phpWiki, a wiki engine
written in PHP. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2007-2024
    
    It was discovered that phpWiki performs insufficient file name 
    validation, which allows unrestricted file uploads.
    
CVE-2007-2025
    
    It was discovered that phpWiki performs insufficient file name 
    validation, which allows unrestricted file uploads.
    
CVE-2007-3193
    
    If the configuration lacks a nonzero PASSWORD_LENGTH_MINIMUM,
    phpWiki might allow remote attackers to bypass authentication via
    an empty password, which causes ldap_bind to return true when used
    with certain LDAP implementations.
    

The old stable distribution (sarge) does not contain phpwiki packages.


For the stable distribution (etch) these problems have been fixed in
version 1.3.12p3-5etch1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1371');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpwiki package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1371] DSA-1371-1 phpwiki");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1371-1 phpwiki");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpwiki', release: '4.0', reference: '1.3.12p3-5etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
