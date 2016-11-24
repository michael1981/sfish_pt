# This script was automatically generated from the dsa-653
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16237);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "653");
 script_cve_id("CVE-2005-0084");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-653 security update');
 script_set_attribute(attribute: 'description', value:
'A buffer overflow has been detected in the X11 dissector of ethereal,
a commonly used network traffic analyser.  A remote attacker may be
able to overflow a buffer using a specially crafted IP packet.  More
problems have been discovered which don\'t apply to the version in
woody but are fixed in sid as well.
For the stable distribution (woody) this problem has been fixed in
version 0.9.4-1woody11.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-653');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ethereal package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA653] DSA-653-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-653-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody11');
deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody11');
deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody11');
deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody11');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
