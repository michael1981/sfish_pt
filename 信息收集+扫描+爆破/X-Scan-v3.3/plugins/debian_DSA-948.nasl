# This script was automatically generated from the dsa-948
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22814);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "948");
 script_cve_id("CVE-2006-0019");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-948 security update');
 script_set_attribute(attribute: 'description', value:
'Maksim Orlovich discovered that the kjs Javascript interpreter, used
in the Konqueror web browser and in other parts of KDE, performs
insufficient bounds checking when parsing UTF-8 encoded Uniform Resource
Identifiers, which may lead to a heap based buffer overflow and the
execution of arbitrary code.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 3.3.2-6.4
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-948');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kdelibs package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA948] DSA-948-1 kdelibs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-948-1 kdelibs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kdelibs', release: '3.1', reference: '3.3.2-6.4');
deb_check(prefix: 'kdelibs-bin', release: '3.1', reference: '3.3.2-6.4');
deb_check(prefix: 'kdelibs-data', release: '3.1', reference: '3.3.2-6.4');
deb_check(prefix: 'kdelibs4', release: '3.1', reference: '3.3.2-6.4');
deb_check(prefix: 'kdelibs4-dev', release: '3.1', reference: '3.3.2-6.4');
deb_check(prefix: 'kdelibs4-doc', release: '3.1', reference: '3.3.2-6.4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
