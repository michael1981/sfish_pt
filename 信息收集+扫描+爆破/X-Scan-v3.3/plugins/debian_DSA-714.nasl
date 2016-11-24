# This script was automatically generated from the dsa-714
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18143);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "714");
 script_cve_id("CVE-2005-1046");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-714 security update');
 script_set_attribute(attribute: 'description', value:
'KDE security team discovered several vulnerabilities in the PCX and
other image file format readers in the KDE core libraries, some of
them exploitable to execute arbitrary code.  To a small extent the
packages in woody are affected as well.
For the stable distribution (woody) this problem has been fixed in
version 2.2.2-13.woody.14.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-714');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kdelibs packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA714] DSA-714-1 kdelibs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-714-1 kdelibs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kdelibs-dev', release: '3.0', reference: '2.2.2-13.woody.14');
deb_check(prefix: 'kdelibs3', release: '3.0', reference: '2.2.2-13.woody.14');
deb_check(prefix: 'kdelibs3-bin', release: '3.0', reference: '2.2.2-13.woody.14');
deb_check(prefix: 'kdelibs3-cups', release: '3.0', reference: '2.2.2-13.woody.14');
deb_check(prefix: 'kdelibs3-doc', release: '3.0', reference: '2.2.2-13.woody.14');
deb_check(prefix: 'libarts', release: '3.0', reference: '2.2.2-13.woody.14');
deb_check(prefix: 'libarts-alsa', release: '3.0', reference: '2.2.2-13.woody.14');
deb_check(prefix: 'libarts-dev', release: '3.0', reference: '2.2.2-13.woody.14');
deb_check(prefix: 'libkmid', release: '3.0', reference: '2.2.2-13.woody.14');
deb_check(prefix: 'libkmid-alsa', release: '3.0', reference: '2.2.2-13.woody.14');
deb_check(prefix: 'libkmid-dev', release: '3.0', reference: '2.2.2-13.woody.14');
deb_check(prefix: 'kdelibs', release: '3.0', reference: '2.2.2-13.woody.14');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
