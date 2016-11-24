# This script was automatically generated from the dsa-1789
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38691);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1789");
 script_cve_id("CVE-2008-2107", "CVE-2008-2108", "CVE-2008-5557", "CVE-2008-5624", "CVE-2008-5658", "CVE-2008-5814", "CVE-2009-0754");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1789 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the PHP&nbsp;5
hypertext preprocessor. The Common Vulnerabilities and Exposures
project identifies the following problems.
The following four vulnerabilities have already been fixed in the stable
(lenny) version of php5 prior to the release of lenny. This update now
addresses them for etch (oldstable) as well:
    The GENERATE_SEED macro has several problems that make predicting
    generated random numbers easier, facilitating attacks against measures
    that use rand() or mt_rand() as part of a protection.
CVE-2008-5557
    A buffer overflow in the mbstring extension allows attackers to execute
    arbitrary code via a crafted string containing an HTML entity.
CVE-2008-5624
    The page_uid and page_gid variables are not correctly set, allowing
    use of some functionality intended to be restricted to root.
CVE-2008-5658
    Directory traversal vulnerability in the ZipArchive::extractTo function
    allows attackers to write arbitrary files via a ZIP file with a file
    whose name contains .. (dot dot) sequences.
This update also addresses the following three vulnerabilities for both
oldstable (etch) and stable (lenny):
CVE-2008-5814
    Cross-site scripting (XSS) vulnerability, when display_errors is enabled,
    allows remote attackers to inject arbitrary web script or HTML.
CVE-2009-0754
    When running on Apache, PHP allows local users to modify behavior of
    other sites hosted on the same web server by modifying the
    mbstring.func_overload setting within .htaccess, which causes this
    setting to be applied to other virtual hosts on the same server. 
CVE-2009-1271
    The JSON_parser function allows a denial of service (segmentation fault)
    via a malformed string to the json_decode API function.
Furthermore, two updates originally scheduled for the next point update for
oldstable are included in the etch package:
  Let PHP use the system timezone database instead of the embedded
    timezone database which is out of date.
  From the source tarball, the unused \'dbase\' module has been removed
    which contained licensing problems.
For the old stable distribution (etch), these problems have been fixed in
version 5.2.0+dfsg-8+etch15.
For the stable distribution (lenny), these problems have been fixed in
version 5.2.6.dfsg.1-1+lenny3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1789');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your php5 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1789] DSA-1789-1 php5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1789-1 php5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-php5', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'libapache2-mod-php5', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php-pear', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-cgi', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-cli', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-common', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-curl', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-dev', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-gd', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-imap', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-interbase', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-ldap', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-mcrypt', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-mhash', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-mysql', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-odbc', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-pgsql', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-pspell', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-recode', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-snmp', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-sqlite', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-sybase', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-tidy', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-xmlrpc', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'php5-xsl', release: '4.0', reference: '5.2.0+dfsg-8+etch15');
deb_check(prefix: 'libapache2-mod-php5', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'libapache2-mod-php5filter', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php-pear', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-cgi', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-cli', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-common', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-curl', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-dbg', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-dev', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-gd', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-gmp', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-imap', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-interbase', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-ldap', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-mcrypt', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-mhash', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-mysql', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-odbc', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-pgsql', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-pspell', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-recode', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-snmp', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-sqlite', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-sybase', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-tidy', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-xmlrpc', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
deb_check(prefix: 'php5-xsl', release: '5.0', reference: '5.2.6.dfsg.1-1+lenny3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
