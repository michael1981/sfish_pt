# This script was automatically generated from the dsa-774
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19430);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "774");
 script_cve_id("CVE-2005-2335");
 script_bugtraq_id(14349);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-774 security update');
 script_set_attribute(attribute: 'description', value:
'Edward Shornock discovered a bug in the UIDL handling code of
fetchmail, a common POP3, APOP and IMAP mail fetching utility.  A
malicious POP3 server could exploit this problem and inject arbitrary
code that will be executed on the victim host.  If fetchmail is
running as root, this becomes a root exploit.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 6.2.5-12sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-774');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your fetchmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA774] DSA-774-1 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-774-1 fetchmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fetchmail', release: '3.1', reference: '6.2.5-12sarge1');
deb_check(prefix: 'fetchmail-ssl', release: '3.1', reference: '6.2.5-12sarge1');
deb_check(prefix: 'fetchmailconf', release: '3.1', reference: '6.2.5-12sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
