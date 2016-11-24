# This script was automatically generated from the dsa-1572
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32306);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1572");
 script_cve_id("CVE-2007-3806", "CVE-2008-1384", "CVE-2008-2050", "CVE-2008-2051");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1572 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in PHP, a server-side,
HTML-embedded scripting language. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2007-3806
    The glob function allows context-dependent attackers to cause
    a denial of service and possibly execute arbitrary code via
    an invalid value of the flags parameter.
CVE-2008-1384
    Integer overflow allows context-dependent attackers to cause
    a denial of service and possibly have other impact via a
    printf format parameter with a large width specifier.
CVE-2008-2050
    Stack-based buffer overflow in the FastCGI SAPI.
CVE-2008-2051
    The escapeshellcmd API function could be attacked via
    incomplete multibyte chars.
For the stable distribution (etch), these problems have been fixed in
version 5.2.0-8+etch11.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1572');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your php5 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1572] DSA-1572-1 php5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1572-1 php5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-php5', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'libapache2-mod-php5', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php-pear', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-cgi', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-cli', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-common', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-curl', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-dev', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-gd', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-imap', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-interbase', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-ldap', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-mcrypt', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-mhash', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-mysql', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-odbc', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-pgsql', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-pspell', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-recode', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-snmp', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-sqlite', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-sybase', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-tidy', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-xmlrpc', release: '4.0', reference: '5.2.0-8+etch11');
deb_check(prefix: 'php5-xsl', release: '4.0', reference: '5.2.0-8+etch11');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
