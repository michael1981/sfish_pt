# This script was automatically generated from the dsa-872
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22738);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "872");
 script_cve_id("CVE-2005-2971");
 script_bugtraq_id(15060);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-872 security update');
 script_set_attribute(attribute: 'description', value:
'Chris Evans discovered a buffer overflow in the RTF importer of kword,
a word processor for the KDE Office Suite that can lead to the
execution of arbitrary code.
The old stable distribution (woody) does not contain a kword package.
For the stable distribution (sarge) this problem has been fixed in
version 1.3.5-4.sarge.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-872');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kword package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA872] DSA-872-1 koffice");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-872-1 koffice");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'karbon', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'kchart', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'kformula', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'kivio', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'kivio-data', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'koffice', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'koffice-data', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'koffice-dev', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'koffice-doc-html', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'koffice-libs', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'koshell', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'kpresenter', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'kspread', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'kugar', release: '3.1', reference: '1.3.5-4.sarge.1');
deb_check(prefix: 'kword', release: '3.1', reference: '1.3.5-4.sarge.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
