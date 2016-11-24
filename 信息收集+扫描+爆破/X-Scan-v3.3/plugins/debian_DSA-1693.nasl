# This script was automatically generated from the dsa-1693
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35276);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1693");
 script_cve_id("CVE-2007-2865", "CVE-2007-5728", "CVE-2008-5587");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1693 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in phpPgAdmin, a tool
to administrate PostgreSQL database over the web. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2865
    
    Cross-site scripting vulnerability allows remote attackers to inject
    arbitrary web script or HTML via the server parameter.
    
CVE-2007-5728
    
    Cross-site scripting vulnerability allows remote attackers to inject
    arbitrary web script or HTML via PHP_SELF.
    
CVE-2008-5587
    
    Directory traversal vulnerability allows remote attackers to read
    arbitrary files via _language parameter.
    

For the stable distribution (etch), these problems have been fixed in
version 4.0.1-3.1etch2.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1693');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phppgadmin package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1693] DSA-1693-2 phppgadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1693-2 phppgadmin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phppgadmin', release: '4.0', reference: '4.0.1-3.1etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
