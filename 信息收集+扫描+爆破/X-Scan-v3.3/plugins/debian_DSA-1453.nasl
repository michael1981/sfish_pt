# This script was automatically generated from the dsa-1453
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29872);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1453");
 script_cve_id("CVE-2007-3382", "CVE-2007-3385", "CVE-2007-5461");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1453 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Tomcat
servlet and JSP engine. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2007-3382
    
    It was discovered that single quotes (\') in cookies were treated
    as a delimiter, which could lead to an information leak.
    
CVE-2007-3385
    
    It was discovered that the character sequence \\" in cookies was
    handled incorrectly, which could lead to an information leak.
    
CVE-2007-5461
    
    It was discovered that the WebDAV servlet is vulnerable to absolute
    path traversal.
    

The old stable distribution (sarge) doesn\'t contain tomcat5.


For the stable distribution (etch), these problems have been fixed in
version 5.0.30-12etch1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1453');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tomcat5 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1453] DSA-1453-1 tomcat5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1453-1 tomcat5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtomcat5-java', release: '4.0', reference: '5.0.30-12etch1');
deb_check(prefix: 'tomcat5', release: '4.0', reference: '5.0.30-12etch1');
deb_check(prefix: 'tomcat5-admin', release: '4.0', reference: '5.0.30-12etch1');
deb_check(prefix: 'tomcat5-webapps', release: '4.0', reference: '5.0.30-12etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
