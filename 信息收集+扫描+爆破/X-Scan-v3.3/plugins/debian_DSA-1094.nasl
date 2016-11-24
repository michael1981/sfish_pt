# This script was automatically generated from the dsa-1094
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22636);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1094");
 script_cve_id("CVE-2005-2430");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1094 security update');
 script_set_attribute(attribute: 'description', value:
'Joxean Koret discovered several cross-site scripting vulnerabilities in
Gforge, an online collaboration suite for software development, which
allow injection of web script code.
The old stable distribution (woody) does not contain gforge packages.
For the stable distribution (sarge) this problem has been fixed in
version 3.1-31sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1094');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gforge package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1094] DSA-1094-1 gforge");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1094-1 gforge");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gforge', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'gforge-common', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'gforge-cvs', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'gforge-db-postgresql', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'gforge-dns-bind9', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'gforge-ftp-proftpd', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'gforge-ldap-openldap', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'gforge-lists-mailman', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'gforge-mta-exim', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'gforge-mta-exim4', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'gforge-mta-postfix', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'gforge-shell-ldap', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'gforge-sourceforge-transition', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'gforge-web-apache', release: '3.1', reference: '3.1-31sarge1');
deb_check(prefix: 'sourceforge', release: '3.1', reference: '3.1-31sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
