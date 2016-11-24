# This script was automatically generated from the dsa-1292
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25229);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1292");
 script_cve_id("CVE-2007-0242");
 script_bugtraq_id(23269);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1292 security update');
 script_set_attribute(attribute: 'description', value:
'Andreas Nolden discovered a bug in the UTF8 decoding routines in
qt4-x11, a C++ GUI library framework, that could allow remote
attackers to conduct cross-site scripting (XSS) and directory
traversal attacks via long sequences that decode to dangerous
metacharacters.
For the stable distribution (etch), this problem has been fixed in version
4.2.1-2etch1.
For the testing and unstable distribution (lenny and sid, respectively),
this problem has been fixed in version 4.2.2-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1292');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your qt4-x11 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1292] DSA-1292-1 qt4-x11");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1292-1 qt4-x11");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libqt4-core', release: '4.0', reference: '4.2.1-2etch1');
deb_check(prefix: 'libqt4-debug', release: '4.0', reference: '4.2.1-2etch1');
deb_check(prefix: 'libqt4-dev', release: '4.0', reference: '4.2.1-2etch1');
deb_check(prefix: 'libqt4-gui', release: '4.0', reference: '4.2.1-2etch1');
deb_check(prefix: 'libqt4-qt3support', release: '4.0', reference: '4.2.1-2etch1');
deb_check(prefix: 'libqt4-sql', release: '4.0', reference: '4.2.1-2etch1');
deb_check(prefix: 'qt4-designer', release: '4.0', reference: '4.2.1-2etch1');
deb_check(prefix: 'qt4-dev-tools', release: '4.0', reference: '4.2.1-2etch1');
deb_check(prefix: 'qt4-doc', release: '4.0', reference: '4.2.1-2etch1');
deb_check(prefix: 'qt4-qtconfig', release: '4.0', reference: '4.2.1-2etch1');
deb_check(prefix: 'qt4-x11', release: '4.0', reference: '4.2.1-2etch1');
deb_check(prefix: 'qt4-x11', release: '5.0', reference: '4.2.2-2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
