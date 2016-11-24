# This script was automatically generated from the dsa-1248
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24025);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1248");
 script_cve_id("CVE-2006-5876");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1248 security update');
 script_set_attribute(attribute: 'description', value:
'Roland Lezuo and Josselin Mouette discovered that the libsoup HTTP
library performs insufficient sanitising when parsing HTTP headers,
which might lead to denial of service.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.3-2sarge1.
For the upcoming stable distribution (etch) this problem has been
fixed in version 2.2.98-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1248');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libsoup package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1248] DSA-1248-1 libsoup");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1248-1 libsoup");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libsoup2.2-7', release: '3.1', reference: '2.2.3-2sarge1');
deb_check(prefix: 'libsoup2.2-dev', release: '3.1', reference: '2.2.3-2sarge1');
deb_check(prefix: 'libsoup2.2-doc', release: '3.1', reference: '2.2.3-2sarge1');
deb_check(prefix: 'libsoup', release: '4.0', reference: '2.2.98-2');
deb_check(prefix: 'libsoup', release: '3.1', reference: '2.2.3-2sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
