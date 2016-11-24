# This script was automatically generated from the dsa-1019
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22561);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1019");
 script_cve_id("CVE-2006-1244");
 script_bugtraq_id(16748);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1019 security update');
 script_set_attribute(attribute: 'description', value:
'Derek Noonburg has fixed several potential vulnerabilities in xpdf,
the Portable Document Format (PDF) suite, which is also present in
koffice, the KDE Office Suite.
The old stable distribution (woody) does not contain koffice packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.3.5-4.sarge.3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1019');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your koffice packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1019] DSA-1019-1 koffice");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1019-1 koffice");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'karbon', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'kchart', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'kformula', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'kivio', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'kivio-data', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'koffice', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'koffice-data', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'koffice-dev', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'koffice-doc-html', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'koffice-libs', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'koshell', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'kpresenter', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'kspread', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'kugar', release: '3.1', reference: '1.3.5-4.sarge.3');
deb_check(prefix: 'kword', release: '3.1', reference: '1.3.5-4.sarge.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
