# This script was automatically generated from the dsa-531
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15368);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "531");
 script_cve_id("CVE-2004-0594", "CVE-2004-0595");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-531 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities were discovered in php4:
   The memory_limit functionality in PHP 4.x up to
   4.3.7, and 5.x up to 5.0.0RC3, under certain conditions such as
   when register_globals is enabled, allows remote attackers to
   execute arbitrary code by triggering a memory_limit abort during
   execution of the zend_hash_init function and overwriting a
   HashTable destructor pointer before the initialization of key data
   structures is complete.
   The strip_tags function in PHP 4.x up to 4.3.7, and
   5.x up to 5.0.0RC3, does not filter null (\\0) characters within tag
   names when restricting input to allowed tags, which allows
   dangerous tags to be processed by web browsers such as Internet
   Explorer and Safari, which ignore null characters and facilitate
   the exploitation of cross-site scripting (XSS) vulnerabilities.
For the current stable distribution (woody), these problems have been
fixed in version 4.1.2-7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-531');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-531
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA531] DSA-531-1 php4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-531-1 php4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'caudium-php4', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-cgi', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-curl', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-dev', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-domxml', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-gd', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-imap', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-ldap', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-mcal', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-mhash', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-mysql', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-odbc', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-pear', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-recode', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-snmp', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-sybase', release: '3.0', reference: '4.1.2-7');
deb_check(prefix: 'php4-xslt', release: '3.0', reference: '4.1.2-7');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
