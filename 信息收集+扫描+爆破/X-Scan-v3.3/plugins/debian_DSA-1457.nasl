# This script was automatically generated from the dsa-1457
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29904);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1457");
 script_cve_id("CVE-2007-6598");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1457 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that Dovecot, a POP3 and IMAP server, only when used
# Remark: "base" refers to a variable(?!) and should not contain something as
# base = %r!
with LDAP authentication and <q>base</q> contains variables, could allow
a user to log in to the account of another user with the same password.


The old stable distribution (sarge) is not affected.


For the stable distribution (etch), this problem has been fixed in
version 1.0.rc15-2etch3.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1457');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your dovecot packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1457] DSA-1457-1 dovecot");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1457-1 dovecot");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'dovecot-common', release: '4.0', reference: '1.0.rc15-2etch3');
deb_check(prefix: 'dovecot-imapd', release: '4.0', reference: '1.0.rc15-2etch3');
deb_check(prefix: 'dovecot-pop3d', release: '4.0', reference: '1.0.rc15-2etch3');
deb_check(prefix: 'dovecot', release: '4.0', reference: '1.0.rc15-2etch3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
