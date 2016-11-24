# This script was automatically generated from the dsa-1268
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24835);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1268");
 script_cve_id("CVE-2007-0002");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1268 security update');
 script_set_attribute(attribute: 'description', value:
'iDefense reported several integer overflow bugs in libwpd, a library
for handling WordPerfect documents.  Attackers were able to exploit
these with carefully crafted Word Perfect files that could cause an
application linked with libwpd to crash or possibly execute arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 0.8.1-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1268');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libwpd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1268] DSA-1268-1 libwpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1268-1 libwpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libwpd-stream8', release: '3.1', reference: '0.8.1-1sarge1');
deb_check(prefix: 'libwpd-stream8c2a', release: '3.1', reference: '0.8.7-6');
deb_check(prefix: 'libwpd-tools', release: '3.1', reference: '0.8.7-6');
deb_check(prefix: 'libwpd8', release: '3.1', reference: '0.8.1-1sarge1');
deb_check(prefix: 'libwpd8-dev', release: '3.1', reference: '0.8.7-6');
deb_check(prefix: 'libwpd8-doc', release: '3.1', reference: '0.8.7-6');
deb_check(prefix: 'libwpd8c2a', release: '3.1', reference: '0.8.7-6');
deb_check(prefix: 'libwpd', release: '3.1', reference: '0.8.1-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
