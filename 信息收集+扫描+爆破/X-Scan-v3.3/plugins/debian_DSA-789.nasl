# This script was automatically generated from the dsa-789
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19532);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "789");
 script_cve_id("CVE-2005-1751", "CVE-2005-1921", "CVE-2005-2498");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-789 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been found in PHP4, the
server-side, HTML-embedded scripting language.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    Eric Romang discovered insecure temporary files in the shtool
    utility shipped with PHP that can exploited by a local attacker to
    overwrite arbitrary files.  Only this vulnerability affects
    packages in oldstable.
    GulfTech has discovered that PEAR XML_RPC is vulnerable to a
    remote PHP code execution vulnerability that may allow an attacker
    to compromise a vulnerable server.
    Stefan Esser discovered another vulnerability in the XML-RPC
    libraries that allows injection of arbitrary PHP code into eval()
    statements.
For the old stable distribution (woody) these problems have been fixed in
version 4.1.2-7.woody5.
For the stable distribution (sarge) these problems have been fixed in
version 4.3.10-16.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-789');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your PHP packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA789] DSA-789-1 php4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-789-1 php4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'caudium-php4', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-cgi', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-curl', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-dev', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-domxml', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-gd', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-imap', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-ldap', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-mcal', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-mhash', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-mysql', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-odbc', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-pear', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-recode', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-snmp', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-sybase', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'php4-xslt', release: '3.0', reference: '4.1.2-7.woody5');
deb_check(prefix: 'libapache-mod-php4', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'libapache2-mod-php4', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-cgi', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-cli', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-common', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-curl', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-dev', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-domxml', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-gd', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-imap', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-ldap', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-mcal', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-mhash', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-mysql', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-odbc', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-pear', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-recode', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-snmp', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-sybase', release: '3.1', reference: '4.3.10-16');
deb_check(prefix: 'php4-xslt', release: '3.1', reference: '4.3.10-16');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
