# This script was automatically generated from the dsa-1444
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29838);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "1444");
 script_cve_id("CVE-2007-3799", "CVE-2007-3998", "CVE-2007-4657", "CVE-2007-4658", "CVE-2007-4660", "CVE-2007-4662", "CVE-2007-5898");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1444 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the patch for CVE-2007-4659 could lead to
regressions in some scenarios. The fix has been reverted for now,
a revised update will be provided in a future PHP DSA.

For reference the original advisory below:

Several remote vulnerabilities have been discovered in PHP, a
server-side, HTML-embedded scripting language. The Common 
Vulnerabilities and Exposures project identifies the following
problems:

CVE-2007-3799
    
    It was discovered that the session_start() function allowed the
    insertion of attributes into the session cookie.
    
CVE-2007-3998
    
    Mattias Bengtsson and Philip Olausson discovered that a
    programming error in the implementation of the wordwrap() function
    allowed denial of service through an infinite loop.
    
CVE-2007-4658
    
    Stanislav Malyshev discovered that a format string vulnerability
    in the money_format() function could allow the execution of
    arbitrary code.
    
CVE-2007-4659
    
    Stefan Esser discovered that execution control flow inside the
    zend_alter_ini_entry() function is handled incorrectly in case
    of a memory limit violation.
    
CVE-2007-4660
    
    Gerhard Wagner discovered an integer overflow inside the
    chunk_split() function.
    
CVE-2007-5898
    
    Rasmus Lerdorf discovered that incorrect parsing of multibyte
    sequences may lead to disclosure of memory contents.
    
CVE-2007-5899
    
    It was discovered that the output_add_rewrite_var() function could
    leak session ID information, resulting in information disclosure.
    

This update also fixes two bugs from the PHP 5.2.4 release which
don\'t have security impact according to the Debian PHP security policy
(CVE-2007-4657 and CVE-2007-4662), but which are fixed nonetheless.


The old stable distribution (sarge) doesn\'t contain php5.


For the stable distribution (etch), these problems have been fixed in
version 5.2.0-8+etch10.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1444');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your php5 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1444] DSA-1444-2 php5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1444-2 php5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-php5', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'libapache2-mod-php5', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php-pear', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-cgi', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-cli', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-common', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-curl', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-dev', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-gd', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-imap', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-interbase', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-ldap', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-mcrypt', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-mhash', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-mysql', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-odbc', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-pgsql', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-pspell', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-recode', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-snmp', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-sqlite', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-sybase', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-tidy', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-xmlrpc', release: '4.0', reference: '5.2.0-8+etch10');
deb_check(prefix: 'php5-xsl', release: '4.0', reference: '5.2.0-8+etch10');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
