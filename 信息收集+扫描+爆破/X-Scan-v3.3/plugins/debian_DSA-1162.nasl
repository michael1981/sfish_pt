# This script was automatically generated from the dsa-1162
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22704);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1162");
 script_cve_id("CVE-2006-4197");
 script_bugtraq_id(19508);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1162 security update');
 script_set_attribute(attribute: 'description', value:
'Luigi Auriemma discovered several buffer overflows in libmusicbrainz,
a CD index library, that allow remote attackers to cause a denial of
service or execute arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 2.0.2-10sarge1 and 2.1.1-3sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1162');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libmusicbrainz packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1162] DSA-1162-1 libmusicbrainz-2.0");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1162-1 libmusicbrainz-2.0");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmusicbrainz2', release: '3.1', reference: '2.0.2-10sarge1');
deb_check(prefix: 'libmusicbrainz2-dev', release: '3.1', reference: '2.0.2-10sarge1');
deb_check(prefix: 'libmusicbrainz4', release: '3.1', reference: '2.1.1-3sarge1');
deb_check(prefix: 'libmusicbrainz4-dev', release: '3.1', reference: '2.1.1-3sarge1');
deb_check(prefix: 'python-musicbrainz', release: '3.1', reference: '2.0.2-10sarge1');
deb_check(prefix: 'python2.1-musicbrainz', release: '3.1', reference: '2.0.2-10sarge1');
deb_check(prefix: 'python2.2-musicbrainz', release: '3.1', reference: '2.0.2-10sarge1');
deb_check(prefix: 'python2.3-musicbrainz', release: '3.1', reference: '2.0.2-10sarge1');
deb_check(prefix: 'libmusicbrainz-2.0,', release: '3.1', reference: '2.0.2-10sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
