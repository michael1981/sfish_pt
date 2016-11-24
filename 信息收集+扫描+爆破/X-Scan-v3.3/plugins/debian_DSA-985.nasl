# This script was automatically generated from the dsa-985
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22851);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "985");
 script_cve_id("CVE-2006-0645");
 script_bugtraq_id(16568);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-985 security update');
 script_set_attribute(attribute: 'description', value:
'Evgeny Legerov discovered several out-of-bounds memory accesses in the
DER decoding component of the Tiny ASN.1 Library that allows
attackers to crash the DER decoder and possibly execute arbitrary code.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 2_0.2.10-3sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-985');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libtasn1 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA985] DSA-985-1 libtasn1-2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-985-1 libtasn1-2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtasn1-2', release: '3.1', reference: '0.2.10-3sarge1');
deb_check(prefix: 'libtasn1-2-dev', release: '3.1', reference: '0.2.10-3sarge1');
deb_check(prefix: 'libtasn1', release: '3.1', reference: '2_0.2.10-3sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
