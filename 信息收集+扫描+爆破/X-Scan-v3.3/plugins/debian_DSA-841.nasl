# This script was automatically generated from the dsa-841
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19845);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "841");
 script_cve_id("CVE-2005-2878");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-841 security update');
 script_set_attribute(attribute: 'description', value:
'A format string vulnerability has been discovered in GNU mailutils
which contains utilities for handling mail that allows a remote
attacker to execute arbitrary code on the IMAP server.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 0.6.1-4sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-841');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mailutils package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA841] DSA-841-1 mailutils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-841-1 mailutils");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmailutils0', release: '3.1', reference: '0.6.1-4sarge1');
deb_check(prefix: 'libmailutils0-dev', release: '3.1', reference: '0.6.1-4sarge1');
deb_check(prefix: 'mailutils', release: '3.1', reference: '0.6.1-4sarge1');
deb_check(prefix: 'mailutils-comsatd', release: '3.1', reference: '0.6.1-4sarge1');
deb_check(prefix: 'mailutils-doc', release: '3.1', reference: '0.6.1-4sarge1');
deb_check(prefix: 'mailutils-imap4d', release: '3.1', reference: '0.6.1-4sarge1');
deb_check(prefix: 'mailutils-mh', release: '3.1', reference: '0.6.1-4sarge1');
deb_check(prefix: 'mailutils-pop3d', release: '3.1', reference: '0.6.1-4sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
