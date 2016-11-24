# This script was automatically generated from the dsa-1283
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25100);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1283");
 script_cve_id("CVE-2007-1286", "CVE-2007-1375", "CVE-2007-1376", "CVE-2007-1380", "CVE-2007-1453", "CVE-2007-1454", "CVE-2007-1521");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1283 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in PHP, a
server-side, HTML-embedded scripting language, which may lead to the
execution of arbitrary code. The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2007-1286
    Stefan Esser discovered an overflow in the object reference handling
    code of the unserialize() function, which allows the execution of
    arbitrary code if malformed input is passed from an application.
CVE-2007-1375
    Stefan Esser discovered that an integer overflow in the substr_compare()
    function allows information disclosure of heap memory.
CVE-2007-1376
    Stefan Esser discovered that insufficient validation of shared memory
    functions allows the disclosure of heap memory.
CVE-2007-1380
    Stefan Esser discovered that the session handler performs
    insufficient validation of variable name length values, which allows
    information disclosure through a heap information leak.
CVE-2007-1453
    Stefan Esser discovered that the filtering framework performs insufficient
    input validation, which allows the execution of arbitrary code through a
    buffer underflow.
CVE-2007-1454
    Stefan Esser discovered that the filtering framework can be bypassed 
    with a special whitespace character.
CVE-2007-1521
    Stefan Esser discovered a double free vulnerability in the
    session_regenerate_id() function, which allows the execution of
    arbitrary code. 
CVE-2007-1583
    Stefan Esser discovered that a programming error in the mb_parse_str()
    function allows the activation of <q>register_globals</q>.
CVE-2007-1700
    Stefan Esser discovered that the session extension incorrectly maintains
    the reference count of session variables, which allows the execution of
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
CVE-2007-1824
    Stefan Esser discovered an off-by-one error in the filtering framework, which
    allows the execution of arbitrary code.
CVE-2007-1887
    Stefan Esser discovered that a buffer overflow in the sqlite extension
    allows the execution of arbitrary code.
CVE-2007-1889
    Stefan Esser discovered that the PHP memory manager performs an
    incorrect type cast, which allows the execution of arbitrary code
    through buffer overflows. 
CVE-2007-1900
    Stefan Esser discovered that incorrect validation in the email filter
    extension allows the injection of mail headers.
The oldstable distribution (sarge) doesn\'t include php5.
For the stable distribution (etch) these problems have been fixed
in version 5.2.0-8+etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1283');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your PHP packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1283] DSA-1283-1 php5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1283-1 php5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-php5', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'libapache2-mod-php5', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php-pear', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-cgi', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-cli', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-common', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-curl', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-dev', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-gd', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-imap', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-interbase', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-ldap', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-mcrypt', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-mhash', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-mysql', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-odbc', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-pgsql', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-pspell', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-recode', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-snmp', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-sqlite', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-sybase', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-tidy', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-xmlrpc', release: '4.0', reference: '5.2.0-8+etch3');
deb_check(prefix: 'php5-xsl', release: '4.0', reference: '5.2.0-8+etch3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
