# This script was automatically generated from the dsa-1095
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22637);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "1095");
 script_bugtraq_id(18034);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1095 security update');
 script_set_attribute(attribute: 'description', value:
'Several problems have been discovered in the FreeType 2 font engine.
The Common vulnerabilities and Exposures project identifies the
following problems:
CVE-2006-0747
    Several integer underflows have been discovered which could allow
    remote attackers to cause a denial of service.
CVE-2006-1861
    Chris Evans discovered several integer overflows that lead to a
    denial of service or could possibly even lead to the execution of
    arbitrary code.
CVE-2006-2493
    Several more integer overflows have been discovered which could
    possibly lead to the execution of arbitrary code.
CVE-2006-2661
    A null pointer dereference could cause a denial of service.
For the old stable distribution (woody) these problems have been fixed in
version 2.0.9-1woody1.
For the stable distribution (sarge) these problems have been fixed in
version 2.1.7-2.5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1095');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libfreetype packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1095] DSA-1095-1 freetype");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2006-0747", "CVE-2006-1861", "CVE-2006-2661");
 script_summary(english: "DSA-1095-1 freetype");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'freetype2-demos', release: '3.0', reference: '2.0.9-1woody1');
deb_check(prefix: 'libfreetype6', release: '3.0', reference: '2.0.9-1woody1');
deb_check(prefix: 'libfreetype6-dev', release: '3.0', reference: '2.0.9-1woody1');
deb_check(prefix: 'freetype2-demos', release: '3.1', reference: '2.1.7-2.5');
deb_check(prefix: 'libfreetype6', release: '3.1', reference: '2.1.7-2.5');
deb_check(prefix: 'libfreetype6-dev', release: '3.1', reference: '2.1.7-2.5');
deb_check(prefix: 'freetype', release: '3.1', reference: '2.1.7-2.5');
deb_check(prefix: 'freetype', release: '3.0', reference: '2.0.9-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
