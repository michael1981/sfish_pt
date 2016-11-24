# This script was automatically generated from the dsa-1818
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(39441);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1818");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1818 security update');
 script_set_attribute(attribute: 'description', value:
'Laurent Almeras and Guillaume Smet have discovered a possible SQL
injection vulnerability and cross-site scripting vulnerabilities in
gforge, a collaborative development tool. Due to insufficient input
sanitising, it was possible to inject arbitrary SQL statements and use
several parameters to conduct cross-site scripting attacks.
For the stable distribution (lenny), these problem have been fixed in
version 4.7~rc2-7lenny1.
The oldstable distribution (etch), these problems have been fixed in
version 4.5.14-22etch11.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1818');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gforge packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_bugtraq_id(35424);
 script_name(english: "[DSA1818] DSA-1818-1 gforge");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1818-1 gforge");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gforge', release: '4.0', reference: '4.5.14-22etch11');
deb_check(prefix: 'gforge-common', release: '4.0', reference: '4.5.14-22etch11');
deb_check(prefix: 'gforge-db-postgresql', release: '4.0', reference: '4.5.14-22etch11');
deb_check(prefix: 'gforge-dns-bind9', release: '4.0', reference: '4.5.14-22etch11');
deb_check(prefix: 'gforge-ftp-proftpd', release: '4.0', reference: '4.5.14-22etch11');
deb_check(prefix: 'gforge-ldap-openldap', release: '4.0', reference: '4.5.14-22etch11');
deb_check(prefix: 'gforge-lists-mailman', release: '4.0', reference: '4.5.14-22etch11');
deb_check(prefix: 'gforge-mta-courier', release: '4.0', reference: '4.5.14-22etch11');
deb_check(prefix: 'gforge-mta-exim', release: '4.0', reference: '4.5.14-22etch11');
deb_check(prefix: 'gforge-mta-exim4', release: '4.0', reference: '4.5.14-22etch11');
deb_check(prefix: 'gforge-mta-postfix', release: '4.0', reference: '4.5.14-22etch11');
deb_check(prefix: 'gforge-shell-ldap', release: '4.0', reference: '4.5.14-22etch11');
deb_check(prefix: 'gforge-shell-postgresql', release: '4.0', reference: '4.5.14-22etch11');
deb_check(prefix: 'gforge-web-apache', release: '4.0', reference: '4.5.14-22etch11');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
