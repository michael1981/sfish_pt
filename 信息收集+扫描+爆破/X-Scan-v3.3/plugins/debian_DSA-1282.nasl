# This script was automatically generated from the dsa-1282
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25099);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1282");
 script_cve_id("CVE-2007-1286", "CVE-2007-1380", "CVE-2007-1521", "CVE-2007-1711", "CVE-2007-1718", "CVE-2007-1777");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1282 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in PHP, a
server-side, HTML-embedded scripting language, which may lead to the
execution of arbitrary code. The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2007-1286
    Stefan Esser discovered an overflow in the object reference handling
    code of the unserialize() function, which allows the execution of
    arbitrary code if malformed input is passed from an application.
CVE-2007-1380
    Stefan Esser discovered that the session handler performs
    insufficient validation of variable name length values, which allows
    information disclosure through a heap information leak.
CVE-2007-1521
    Stefan Esser discovered a double free vulnerability in the
    session_regenerate_id() function, which allows the execution of
    arbitrary code. 
CVE-2007-1711
    Stefan Esser discovered a double free vulnerability in the session
    management code, which allows the execution of arbitrary code. 
CVE-2007-1718
    Stefan Esser discovered that the mail() function performs
    insufficient validation of folded mail headers, which allows mail
    header injection.
CVE-2007-1777
    Stefan Esser discovered that the extension to handle ZIP archives
    performs insufficient length checks, which allows the execution of
    arbitrary code.
For the oldstable distribution (sarge) these problems have been fixed in
version 4.3.10-20.
For the stable distribution (etch) these problems have been fixed
in version 4.4.4-8+etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1282');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your PHP packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1282] DSA-1282-1 php4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1282-1 php4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-php4', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'libapache2-mod-php4', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-cgi', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-cli', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-common', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-curl', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-dev', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-domxml', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-gd', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-imap', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-ldap', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-mcal', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-mhash', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-mysql', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-odbc', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-pear', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-recode', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-snmp', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-sybase', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'php4-xslt', release: '3.1', reference: '4.3.10-20');
deb_check(prefix: 'libapache-mod-php4', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'libapache2-mod-php4', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-cgi', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-cli', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-common', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-curl', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-dev', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-domxml', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-gd', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-imap', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-interbase', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-ldap', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-mcal', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-mcrypt', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-mhash', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-mysql', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-odbc', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-pear', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-pgsql', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-pspell', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-recode', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-snmp', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-sybase', release: '4.0', reference: '4.4.4-8+etch2');
deb_check(prefix: 'php4-xslt', release: '4.0', reference: '4.4.4-8+etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
