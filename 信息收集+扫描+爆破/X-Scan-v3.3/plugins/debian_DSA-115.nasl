# This script was automatically generated from the dsa-115
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14952);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "115");
 script_cve_id("CVE-2002-0081");
 script_bugtraq_id(4183);
 script_xref(name: "CERT", value: "297363");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-115 security update');
 script_set_attribute(attribute: 'description', value:
'Stefan Esser, who is also a member of the PHP team, found several
flaws
in the way PHP handles multipart/form-data POST requests (as
described in RFC1867) known as POST fileuploads.  Each of the flaws
could allow an attacker to execute arbitrary code on the victim\'s
system.
For PHP3 flaws contain a broken boundary check and an arbitrary heap
overflow.  For PHP4 they consist of a broken boundary check and a heap
off by one error.
For the stable release of Debian these problems are fixed in version
3.0.18-0potato1.1 of PHP3 and version 4.0.3pl1-0potato3 of PHP4.
For the unstable and testing release of Debian these problems are
fixed in version 3.0.18-22 of PHP3 and version 4.1.2-1 of PHP4.
There is no PHP4 in the stable and unstable distribution for the arm
architecture due to a compiler error.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-115');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your PHP packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA115] DSA-115-1 php");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-115-1 php");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'php3', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-cgi', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-cgi-gd', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-cgi-imap', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-cgi-ldap', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-cgi-magick', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-cgi-mhash', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-cgi-mysql', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-cgi-pgsql', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-cgi-snmp', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-cgi-xml', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-dev', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-doc', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-gd', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-imap', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-ldap', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-magick', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-mhash', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-mysql', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-pgsql', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-snmp', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php3-xml', release: '2.2', reference: '3.0.18-0potato1.1');
deb_check(prefix: 'php4', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-cgi', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-cgi-gd', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-cgi-imap', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-cgi-ldap', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-cgi-mhash', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-cgi-mysql', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-cgi-pgsql', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-cgi-snmp', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-cgi-xml', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-dev', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-gd', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-imap', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-ldap', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-mhash', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-mysql', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-pgsql', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-snmp', release: '2.2', reference: '4.0.3pl1-0potato3');
deb_check(prefix: 'php4-xml', release: '2.2', reference: '4.0.3pl1-0potato3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
