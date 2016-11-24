# This script was automatically generated from the dsa-938
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22804);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "938");
 script_cve_id("CVE-2005-3191", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-938 security update');
 script_set_attribute(attribute: 'description', value:
'"infamous41md" and chris Evans discovered several heap based buffer
overflows in xpdf, the Portable Document Format (PDF) suite, which is
also present in koffice, the KDE Office Suite, and which can lead to a
denial of service by crashing the application or possibly to the
execution of arbitrary code.
The old stable distribution (woody) does not contain koffice packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.3.5-4.sarge.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-938');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your koffice package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA938] DSA-938-1 koffice");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-938-1 koffice");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'karbon', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'kchart', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'kformula', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'kivio', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'kivio-data', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'koffice', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'koffice-data', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'koffice-dev', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'koffice-doc-html', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'koffice-libs', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'koshell', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'kpresenter', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'kspread', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'kugar', release: '3.1', reference: '1.3.5-4.sarge.2');
deb_check(prefix: 'kword', release: '3.1', reference: '1.3.5-4.sarge.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
