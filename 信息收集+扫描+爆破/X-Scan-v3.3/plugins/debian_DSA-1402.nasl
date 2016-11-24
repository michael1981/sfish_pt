# This script was automatically generated from the dsa-1402
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(27819);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1402");
 script_cve_id("CVE-2007-3921");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1402 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp from the Debian Security Audit project discovered that gforge,
a collaborative development tool, used temporary files insecurely which
could allow local users to truncate files upon the system with the privileges
of the gforge user, or create a denial of service attack.
For the old stable distribution (sarge), this problem has been fixed in
version 3.1-31sarge4.
For the stable distribution (etch), this problem has been fixed in version
4.5.14-22etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1402');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gforge package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1402] DSA-1402-1 gforge");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1402-1 gforge");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gforge', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge-common', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge-cvs', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge-db-postgresql', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge-dns-bind9', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge-ftp-proftpd', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge-ldap-openldap', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge-lists-mailman', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge-mta-exim', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge-mta-exim4', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge-mta-postfix', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge-shell-ldap', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge-sourceforge-transition', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge-web-apache', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'sourceforge', release: '3.1', reference: '3.1-31sarge4');
deb_check(prefix: 'gforge', release: '4.0', reference: '4.5.14-22etch3');
deb_check(prefix: 'gforge-common', release: '4.0', reference: '4.5.14-22etch3');
deb_check(prefix: 'gforge-db-postgresql', release: '4.0', reference: '4.5.14-22etch3');
deb_check(prefix: 'gforge-dns-bind9', release: '4.0', reference: '4.5.14-22etch3');
deb_check(prefix: 'gforge-ftp-proftpd', release: '4.0', reference: '4.5.14-22etch3');
deb_check(prefix: 'gforge-ldap-openldap', release: '4.0', reference: '4.5.14-22etch3');
deb_check(prefix: 'gforge-lists-mailman', release: '4.0', reference: '4.5.14-22etch3');
deb_check(prefix: 'gforge-mta-courier', release: '4.0', reference: '4.5.14-22etch3');
deb_check(prefix: 'gforge-mta-exim', release: '4.0', reference: '4.5.14-22etch3');
deb_check(prefix: 'gforge-mta-exim4', release: '4.0', reference: '4.5.14-22etch3');
deb_check(prefix: 'gforge-mta-postfix', release: '4.0', reference: '4.5.14-22etch3');
deb_check(prefix: 'gforge-shell-ldap', release: '4.0', reference: '4.5.14-22etch3');
deb_check(prefix: 'gforge-shell-postgresql', release: '4.0', reference: '4.5.14-22etch3');
deb_check(prefix: 'gforge-web-apache', release: '4.0', reference: '4.5.14-22etch3');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
