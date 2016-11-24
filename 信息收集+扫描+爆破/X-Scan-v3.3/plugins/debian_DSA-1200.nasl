# This script was automatically generated from the dsa-1200
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22927);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1200");
 script_cve_id("CVE-2006-4811");
 script_bugtraq_id(20599);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1200 security update');
 script_set_attribute(attribute: 'description', value:
'An integer overflow has been found in the pixmap handling routines in
the Qt GUI libraries.  This could allow an attacker to cause a denial of
service and possibly execute arbitrary code by providing a specially
crafted image file and inducing the victim to view it in an application
based on Qt.
For the stable distribution (sarge), this problem has been fixed in
version 3:3.3.4-3sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1200');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your qt-x11-free packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1200] DSA-1200-1 qt-x11-free");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1200-1 qt-x11-free");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libqt3-compat-headers', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3-dev', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3-headers', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3-i18n', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3-mt-dev', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3c102', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3c102-ibase', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3c102-mt', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3c102-mt-ibase', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3c102-mt-mysql', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3c102-mt-odbc', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3c102-mt-psql', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3c102-mt-sqlite', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3c102-mysql', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3c102-odbc', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3c102-psql', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'libqt3c102-sqlite', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'qt3-apps-dev', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'qt3-assistant', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'qt3-designer', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'qt3-dev-tools', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'qt3-dev-tools-compat', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'qt3-dev-tools-embedded', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'qt3-doc', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'qt3-examples', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'qt3-linguist', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'qt3-qtconfig', release: '3.1', reference: '3.3.4-3sarge1');
deb_check(prefix: 'qt-x11-free', release: '3.1', reference: '3.3.4-3sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
