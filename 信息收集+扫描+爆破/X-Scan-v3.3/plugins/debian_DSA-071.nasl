# This script was automatically generated from the dsa-071
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14908);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "071");
 script_cve_id("CVE-2001-1009");
 script_bugtraq_id(3164, 3166);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-071 security update');
 script_set_attribute(attribute: 'description', value:
'Salvatore Sanfilippo found two remotely exploitable problems in
fetchmail while doing a security audit. In both the IMAP code
and the POP3 code, the input isn\'t verified even though it\'s used to store
a number in an array. Since
no bounds checking is done this can be used by an attacker to write
arbitrary data in memory. An attacker can use this if they can get a user
to transfer mail from a custom IMAP or POP3 server they control.

This has been fixed in version 5.3.3-3, we recommend that you
update your fetchmail packages immediately.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-071');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-071
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA071] DSA-071-1 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-071-1 fetchmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fetchmail', release: '2.2', reference: '5.3.3-3');
deb_check(prefix: 'fetchmailconf', release: '2.2', reference: '5.3.3-3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
