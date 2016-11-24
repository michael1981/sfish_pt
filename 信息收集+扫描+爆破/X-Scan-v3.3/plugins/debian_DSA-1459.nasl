# This script was automatically generated from the dsa-1459
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29936);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1459");
 script_cve_id("CVE-2008-0173");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1459 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that Gforge, a collaborative development tool, did not
properly sanitise some CGI parameters, allowing SQL injection in scripts
related to RSS exports.


For the old stable distribution (sarge), this problem has been fixed in
version 3.1-31sarge5.


For the stable distribution (etch), this problem has been fixed in
version 4.5.14-22etch4.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1459');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gforge packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1459] DSA-1459-1 gforge");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1459-1 gforge");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gforge', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge-common', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge-cvs', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge-db-postgresql', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge-dns-bind9', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge-ftp-proftpd', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge-ldap-openldap', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge-lists-mailman', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge-mta-exim', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge-mta-exim4', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge-mta-postfix', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge-shell-ldap', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge-sourceforge-transition', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge-web-apache', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'sourceforge', release: '3.1', reference: '3.1-31sarge5');
deb_check(prefix: 'gforge', release: '4.0', reference: '4.5.14-22etch4');
deb_check(prefix: 'gforge-common', release: '4.0', reference: '4.5.14-22etch4');
deb_check(prefix: 'gforge-db-postgresql', release: '4.0', reference: '4.5.14-22etch4');
deb_check(prefix: 'gforge-dns-bind9', release: '4.0', reference: '4.5.14-22etch4');
deb_check(prefix: 'gforge-ftp-proftpd', release: '4.0', reference: '4.5.14-22etch4');
deb_check(prefix: 'gforge-ldap-openldap', release: '4.0', reference: '4.5.14-22etch4');
deb_check(prefix: 'gforge-lists-mailman', release: '4.0', reference: '4.5.14-22etch4');
deb_check(prefix: 'gforge-mta-courier', release: '4.0', reference: '4.5.14-22etch4');
deb_check(prefix: 'gforge-mta-exim', release: '4.0', reference: '4.5.14-22etch4');
deb_check(prefix: 'gforge-mta-exim4', release: '4.0', reference: '4.5.14-22etch4');
deb_check(prefix: 'gforge-mta-postfix', release: '4.0', reference: '4.5.14-22etch4');
deb_check(prefix: 'gforge-shell-ldap', release: '4.0', reference: '4.5.14-22etch4');
deb_check(prefix: 'gforge-shell-postgresql', release: '4.0', reference: '4.5.14-22etch4');
deb_check(prefix: 'gforge-web-apache', release: '4.0', reference: '4.5.14-22etch4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
