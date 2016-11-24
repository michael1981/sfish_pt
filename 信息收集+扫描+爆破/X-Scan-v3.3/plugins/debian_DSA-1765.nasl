# This script was automatically generated from the dsa-1765
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36119);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1765");
 script_cve_id("CVE-2008-3330", "CVE-2008-5917", "CVE-2009-0932");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1765 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been found in horde3, the horde web application
framework. The Common Vulnerabilities and Exposures project identifies
the following problems:
CVE-2009-0932
Gunnar Wrobel discovered a directory traversal vulnerability, which
allows attackers to include and execute arbitrary local files via the
driver parameter in Horde_Image.
CVE-2008-3330
It was discovered that an attacker could perform a cross-site scripting
attack via the contact name, which allows attackers to inject arbitrary
html code. This requires that the attacker has access to create
contacts.
CVE-2008-5917
It was discovered that the horde XSS filter is prone to a cross-site
scripting attack, which allows attackers to inject arbitrary html code.
This is only exploitable when Internet Explorer is used.
For the oldstable distribution (etch), these problems have been fixed in
version 3.1.3-4etch5.
For the stable distribution (lenny), these problems have been fixed in
version 3.2.2+debian0-2, which was already included in the lenny
release.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1765');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your horde3 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1765] DSA-1765-1 horde3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1765-1 horde3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'horde3', release: '4.0', reference: '3.1.3-4etch5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
