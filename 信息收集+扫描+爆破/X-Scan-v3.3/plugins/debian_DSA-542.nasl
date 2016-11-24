# This script was automatically generated from the dsa-542
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15379);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "542");
 script_cve_id("CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-542 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities were discovered in recent versions of Qt, a
commonly used graphic widget set, used in KDE for example.  The first
problem allows an attacker to execute arbitrary code, while the other
two only seem to pose a denial of service danger.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:
    Chris Evans has discovered a heap-based overflow when handling
    8-bit RLE encoded BMP files.
    Marcus Meissner has discovered a crash condition in the XPM
    handling code, which is not yet fixed in Qt 3.3.
    Marcus Meissner has discovered a crash condition in the GIF
    handling code, which is not yet fixed in Qt 3.3.
For the stable distribution (woody) these problems have been fixed in
version 3.0.3-20020329-1woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-542');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your qt packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA542] DSA-542-1 qt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-542-1 qt");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libqt3', release: '3.0', reference: '3.0.3-20020329-1woody2');
deb_check(prefix: 'libqt3-dev', release: '3.0', reference: '3.0.3-20020329-1woody2');
deb_check(prefix: 'libqt3-mt', release: '3.0', reference: '3.0.3-20020329-1woody2');
deb_check(prefix: 'libqt3-mt-dev', release: '3.0', reference: '3.0.3-20020329-1woody2');
deb_check(prefix: 'libqt3-mt-mysql', release: '3.0', reference: '3.0.3-20020329-1woody2');
deb_check(prefix: 'libqt3-mt-odbc', release: '3.0', reference: '3.0.3-20020329-1woody2');
deb_check(prefix: 'libqt3-mysql', release: '3.0', reference: '3.0.3-20020329-1woody2');
deb_check(prefix: 'libqt3-odbc', release: '3.0', reference: '3.0.3-20020329-1woody2');
deb_check(prefix: 'libqxt0', release: '3.0', reference: '3.0.3-20020329-1woody2');
deb_check(prefix: 'qt3-doc', release: '3.0', reference: '3.0.3-20020329-1woody2');
deb_check(prefix: 'qt3-tools', release: '3.0', reference: '3.0.3-20020329-1woody2');
deb_check(prefix: 'qt-copy', release: '3.0', reference: '3.0.3-20020329-1woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
