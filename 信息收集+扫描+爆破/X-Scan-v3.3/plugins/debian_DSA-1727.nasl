# This script was automatically generated from the dsa-1727
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35739);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1727");
 script_cve_id("CVE-2009-0542", "CVE-2009-0543");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1727 security update');
 script_set_attribute(attribute: 'description', value:
'Two SQL injection vulnerabilities have been found in proftpd, a
virtual-hosting FTP daemon.  The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2009-0542
    Shino discovered that proftpd is prone to an SQL injection
    vulnerability via the use of certain characters in the username.
CVE-2009-0543
    TJ Saunders discovered that proftpd is prone to an SQL injection
    vulnerability due to insufficient escaping mechanisms, when
    multybite character encodings are used.
For the stable distribution (lenny), these problems have been fixed in
version 1.3.1-17lenny1.
For the oldstable distribution (etch), these problems will be fixed
soon.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1727');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your proftpd-dfsg package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1727] DSA-1727-1 proftpd-dfsg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1727-1 proftpd-dfsg");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'proftpd', release: '5.0', reference: '1.3.1-17lenny1');
deb_check(prefix: 'proftpd-basic', release: '5.0', reference: '1.3.1-17lenny1');
deb_check(prefix: 'proftpd-doc', release: '5.0', reference: '1.3.1-17lenny1');
deb_check(prefix: 'proftpd-mod-ldap', release: '5.0', reference: '1.3.1-17lenny1');
deb_check(prefix: 'proftpd-mod-mysql', release: '5.0', reference: '1.3.1-17lenny1');
deb_check(prefix: 'proftpd-mod-pgsql', release: '5.0', reference: '1.3.1-17lenny1');
deb_check(prefix: 'proftpd-dfsg', release: '5.0', reference: '1.3.1-17lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
