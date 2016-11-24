# This script was automatically generated from the dsa-168
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15005);
 script_version("$Revision: 1.14 $");
 script_xref(name: "DSA", value: "168");
 script_bugtraq_id(5681);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-168 security update');
 script_set_attribute(attribute: 'description', value:
'Wojciech Purczynski found out that it is possible for scripts to pass
arbitrary text to sendmail as commandline extension when sending a
mail through PHP even when safe_mode is turned on.  Passing 5th
argument should be disabled if PHP is configured in safe_mode, which
is the case for newer PHP versions and for the versions below.  This
does not affect PHP3, though.
Wojciech Purczynski also found out that arbitrary ASCII control
characters may be injected into string arguments of the mail() function.
If mail() arguments are taken from user\'s input it may give the user
ability to alter message content including mail headers.
Ulf Härnhammar discovered that file() and fopen() are vulnerable to
CRLF injection.  An attacker could use it to escape certain
restrictions and add arbitrary text to alleged HTTP requests that are
passed through.
However this only happens if something is passed to these functions
which is neither a valid file name nor a valid url.  Any string that
contains control chars cannot be a valid url.  Before you pass a
string that should be a url to any function you must use urlencode()
to encode it.
Three problems have been identified in PHP:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-168');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your PHP packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA168] DSA-168-1 php");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2002-0985", "CVE-2002-0986", "CVE-2002-1783");
 script_summary(english: "DSA-168-1 php");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'php3', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-cgi', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-cgi-gd', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-cgi-imap', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-cgi-ldap', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-cgi-magick', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-cgi-mhash', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-cgi-mysql', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-cgi-pgsql', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-cgi-snmp', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-cgi-xml', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-dev', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-doc', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-gd', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-imap', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-ldap', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-magick', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-mhash', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-mysql', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-pgsql', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-snmp', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php3-xml', release: '2.2', reference: '3.0.18-0potato1.2');
deb_check(prefix: 'php4', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-cgi', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-cgi-gd', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-cgi-imap', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-cgi-ldap', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-cgi-mhash', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-cgi-mysql', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-cgi-pgsql', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-cgi-snmp', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-cgi-xml', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-dev', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-gd', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-imap', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-ldap', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-mhash', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-mysql', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-pgsql', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-snmp', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'php4-xml', release: '2.2', reference: '4.0.3pl1-0potato4');
deb_check(prefix: 'caudium-php4', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php3', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-cgi', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-cgi-gd', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-cgi-imap', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-cgi-ldap', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-cgi-magick', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-cgi-mhash', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-cgi-mysql', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-cgi-snmp', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-cgi-xml', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-dev', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-doc', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-gd', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-imap', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-ldap', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-magick', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-mhash', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-mysql', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-snmp', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php3-xml', release: '3.0', reference: '3.0.18-23.1woody1');
deb_check(prefix: 'php4', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-cgi', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-curl', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-dev', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-domxml', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-gd', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-imap', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-ldap', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-mcal', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-mhash', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-mysql', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-odbc', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-pear', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-recode', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-snmp', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-sybase', release: '3.0', reference: '4.1.2-5');
deb_check(prefix: 'php4-xslt', release: '3.0', reference: '4.1.2-5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
