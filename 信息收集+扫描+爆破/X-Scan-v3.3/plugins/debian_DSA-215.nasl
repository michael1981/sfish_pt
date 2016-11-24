# This script was automatically generated from the dsa-215
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15052);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "215");
 script_cve_id("CVE-2002-1580");
 script_bugtraq_id(6298);
 script_xref(name: "CERT", value: "740169");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-215 security update');
 script_set_attribute(attribute: 'description', value:
'Timo Sirainen discovered a buffer overflow in the Cyrus IMAP server,
which could be exploited by a remote attacker prior to logging in.  A
malicious user could craft a request to run commands on the server under
the UID and GID of the cyrus server.
For the current stable distribution (woody) this problem has been
fixed in version 1.5.19-9.1.
For the old stable distribution (potato) this problem has been fixed
in version 1.5.19-2.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-215');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cyrus-imapd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA215] DSA-215-1 cyrus-imapd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-215-1 cyrus-imapd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cyrus-admin', release: '2.2', reference: '1.5.19-2.2');
deb_check(prefix: 'cyrus-common', release: '2.2', reference: '1.5.19-2.2');
deb_check(prefix: 'cyrus-dev', release: '2.2', reference: '1.5.19-2.2');
deb_check(prefix: 'cyrus-imapd', release: '2.2', reference: '1.5.19-2.2');
deb_check(prefix: 'cyrus-nntp', release: '2.2', reference: '1.5.19-2.2');
deb_check(prefix: 'cyrus-pop3d', release: '2.2', reference: '1.5.19-2.2');
deb_check(prefix: 'cyrus-admin', release: '3.0', reference: '1.5.19-9.1');
deb_check(prefix: 'cyrus-common', release: '3.0', reference: '1.5.19-9.1');
deb_check(prefix: 'cyrus-dev', release: '3.0', reference: '1.5.19-9.1');
deb_check(prefix: 'cyrus-imapd', release: '3.0', reference: '1.5.19-9.1');
deb_check(prefix: 'cyrus-nntp', release: '3.0', reference: '1.5.19-9.1');
deb_check(prefix: 'cyrus-pop3d', release: '3.0', reference: '1.5.19-9.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
