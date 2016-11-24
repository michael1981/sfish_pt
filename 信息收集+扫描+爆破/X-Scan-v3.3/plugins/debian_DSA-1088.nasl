# This script was automatically generated from the dsa-1088
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22630);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1088");
 script_cve_id("CVE-2005-3863");
 script_bugtraq_id(15600);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1088 security update');
 script_set_attribute(attribute: 'description', value:
'Mehdi Oudad and Kevin Fernandez discovered a buffer overflow in the
ktools library which is used in centericq, a text-mode multi-protocol
instant messenger client, which may lead local or remote attackers to
execute arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 4.5.1-1.1woody2.
For the stable distribution (sarge) this problem has been fixed in
version 4.20.0-1sarge4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1088');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your centericq package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1088] DSA-1088-1 centericq");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1088-1 centericq");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'centericq', release: '3.0', reference: '4.5.1-1.1woody2');
deb_check(prefix: 'centericq', release: '3.1', reference: '4.20.0-1sarge4');
deb_check(prefix: 'centericq-common', release: '3.1', reference: '4.20.0-1sarge4');
deb_check(prefix: 'centericq-fribidi', release: '3.1', reference: '4.20.0-1sarge4');
deb_check(prefix: 'centericq-utf8', release: '3.1', reference: '4.20.0-1sarge4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
