# This script was automatically generated from the dsa-1406
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(28151);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1406");
 script_cve_id("CVE-2006-3548", "CVE-2006-3549", "CVE-2006-4256", "CVE-2007-1473", "CVE-2007-1474");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1406 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Horde web
application framework. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2006-3548
    
    Moritz Naumann discovered that Horde allows remote attackers
    to inject arbitrary web script or HTML in the context of a logged
    in user (cross site scripting).
    
    
    This vulnerability applies to oldstable (sarge) only.
    
CVE-2006-3549
    
    Moritz Naumann discovered that Horde does not properly restrict
    its image proxy, allowing remote attackers to use the server as a
    proxy.
    
    
    This vulnerability applies to oldstable (sarge) only.
    
CVE-2006-4256
    
    Marc Ruef discovered that Horde allows remote attackers to
    include web pages from other sites, which could be useful for
    phishing attacks.
    
    
    This vulnerability applies to oldstable (sarge) only.
    
CVE-2007-1473
    
    Moritz Naumann discovered that Horde allows remote attackers
    to inject arbitrary web script or HTML in the context of a logged
    in user (cross site scripting).
    
    
    This vulnerability applies to both stable (etch) and oldstable (sarge).
    
CVE-2007-1474
    
    iDefense discovered that the cleanup cron script in Horde
    allows local users to delete arbitrary files.
    
    
    This vulnerability applies to oldstable (sarge) only.
    

For the old stable distribution (sarge) these problems have been fixed in
version 3.0.4-4sarge6.


For the stable distribution (etch) these problems have been fixed in
version 3.1.3-4etch1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1406');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your horde3 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1406] DSA-1406-1 horde3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1406-1 horde3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'horde3', release: '3.1', reference: '3.0.4-4sarge6');
deb_check(prefix: 'horde3', release: '4.0', reference: '3.1.3-4etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
