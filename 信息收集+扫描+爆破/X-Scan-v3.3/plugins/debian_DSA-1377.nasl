# This script was automatically generated from the dsa-1377
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(26080);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1377");
 script_cve_id("CVE-2007-4565");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1377 security update');
 script_set_attribute(attribute: 'description', value:
'Matthias Andree discovered that fetchmail, an SSL enabled POP3, APOP 
and IMAP mail gatherer/forwarder, can under certain circumstances 
attempt to dereference a NULL pointer and crash.
For the old stable distribution (sarge), this problem was not present.
For the stable distribution (etch), this problem has been fixed in
version 6.3.6-1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1377');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your fetchmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1377] DSA-1377-2 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1377-2 fetchmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fetchmail', release: '4.0', reference: '6.3.6-1etch1');
deb_check(prefix: 'fetchmailconf', release: '4.0', reference: '6.3.6-1etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
