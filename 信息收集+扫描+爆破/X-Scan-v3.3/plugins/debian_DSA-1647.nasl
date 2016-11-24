# This script was automatically generated from the dsa-1647
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34355);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1647");
 script_cve_id("CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1647 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in PHP, a server-side,
HTML-embedded scripting language. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2008-3658
    Buffer overflow in the imageloadfont function allows a denial
    of service or code execution through a crafted font file.
CVE-2008-3659
    Buffer overflow in the memnstr function allows a denial of
    service  or code execution via a crafted delimiter parameter
    to the explode function.
CVE-2008-3660
    Denial of service is possible in the FastCGI module by a
    remote attacker by making a request with multiple dots
    before the extension.
For the stable distribution (etch), these problems have been fixed in
version 5.2.0-8+etch13.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1647');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your php5 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1647] DSA-1647-1 php5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1647-1 php5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-php5', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'libapache2-mod-php5', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php-pear', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-cgi', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-cli', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-common', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-curl', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-dev', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-gd', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-imap', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-interbase', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-ldap', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-mcrypt', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-mhash', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-mysql', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-odbc', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-pgsql', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-pspell', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-recode', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-snmp', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-sqlite', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-sybase', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-tidy', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-xmlrpc', release: '4.0', reference: '5.2.0-8+etch13');
deb_check(prefix: 'php5-xsl', release: '4.0', reference: '5.2.0-8+etch13');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
