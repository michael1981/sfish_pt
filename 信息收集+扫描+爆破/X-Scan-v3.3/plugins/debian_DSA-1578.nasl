# This script was automatically generated from the dsa-1578
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32379);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1578");
 script_cve_id("CVE-2007-3799", "CVE-2007-3806", "CVE-2007-3998", "CVE-2007-4657", "CVE-2008-2051");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1578 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in PHP version 4, a
server-side, HTML-embedded scripting language. The Common Vulnerabilities
and Exposures project identifies the following problems:
CVE-2007-3799
    The session_start function allows remote attackers to insert
    arbitrary attributes into the session cookie via special characters
    in a cookie that is obtained from various parameters.
CVE-2007-3806
    A denial of service was possible through a malicious script abusing
    the glob() function.
CVE-2007-3998
    Certain maliciously constructed input to the wordwrap() function could
    lead to a denial of service attack.
CVE-2007-4657
    Large len values of the stspn() or strcspn() functions could allow an
    attacker to trigger integer overflows to expose memory or cause denial
    of service.
CVE-2008-2051
    The escapeshellcmd API function could be attacked via incomplete
    multibyte chars.
For the stable distribution (etch), these problems have been fixed in
version 6:4.4.4-8+etch6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1578');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your php4 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1578] DSA-1578-1 php4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1578-1 php4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-php4', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'libapache2-mod-php4', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-cgi', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-cli', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-common', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-curl', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-dev', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-domxml', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-gd', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-imap', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-interbase', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-ldap', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-mcal', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-mcrypt', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-mhash', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-mysql', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-odbc', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-pear', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-pgsql', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-pspell', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-recode', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-snmp', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-sybase', release: '4.0', reference: '4.4.4-8+etch6');
deb_check(prefix: 'php4-xslt', release: '4.0', reference: '4.4.4-8+etch6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
