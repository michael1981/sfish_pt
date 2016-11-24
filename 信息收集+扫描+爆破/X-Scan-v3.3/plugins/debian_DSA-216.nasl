# This script was automatically generated from the dsa-216
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15053);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "216");
 script_cve_id("CVE-2002-1365");
 script_bugtraq_id(6390);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-216 security update');
 script_set_attribute(attribute: 'description', value:
'Stefan Esser of e-matters discovered a buffer overflow in fetchmail,
an SSL enabled POP3, APOP and IMAP mail gatherer/forwarder.  When
fetchmail retrieves a mail all headers that contain addresses are
searched for local addresses.  If a hostname is missing, fetchmail
appends it but doesn\'t reserve enough space for it.  This heap
overflow can be used by remote attackers to crash it or to execute
arbitrary code with the privileges of the user running fetchmail.
For the current stable distribution (woody) this problem has been
fixed in version 5.9.11-6.2 of fetchmail and fetchmail-ssl.
For the old stable distribution (potato) this problem has been fixed
in version 5.3.3-4.3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-216');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your fetchmail packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA216] DSA-216-1 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-216-1 fetchmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fetchmail', release: '2.2', reference: '5.3.3-4.3');
deb_check(prefix: 'fetchmailconf', release: '2.2', reference: '5.3.3-4.3');
deb_check(prefix: 'fetchmail', release: '3.0', reference: '5.9.11-6.2');
deb_check(prefix: 'fetchmail-common', release: '3.0', reference: '5.9.11-6.2');
deb_check(prefix: 'fetchmail-ssl', release: '3.0', reference: '5.9.11-6.2');
deb_check(prefix: 'fetchmailconf', release: '3.0', reference: '5.9.11-6.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
