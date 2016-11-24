# This script was automatically generated from the dsa-1116
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22658);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1116");
 script_cve_id("CVE-2006-3404");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1116 security update');
 script_set_attribute(attribute: 'description', value:
'Henning Makholm discovered a buffer overflow in the XCF loading code
of Gimp, an image editing program. Opening a specially crafted XCF
image might cause the application to execute arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.6-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1116');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gimp package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1116] DSA-1116-1 gimp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1116-1 gimp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gimp', release: '3.1', reference: '2.2.6-1sarge1');
deb_check(prefix: 'gimp-data', release: '3.1', reference: '2.2.6-1sarge1');
deb_check(prefix: 'gimp-helpbrowser', release: '3.1', reference: '2.2.6-1sarge1');
deb_check(prefix: 'gimp-python', release: '3.1', reference: '2.2.6-1sarge1');
deb_check(prefix: 'gimp-svg', release: '3.1', reference: '2.2.6-1sarge1');
deb_check(prefix: 'gimp1.2', release: '3.1', reference: '2.2.6-1sarge1');
deb_check(prefix: 'libgimp2.0', release: '3.1', reference: '2.2.6-1sarge1');
deb_check(prefix: 'libgimp2.0-dev', release: '3.1', reference: '2.2.6-1sarge1');
deb_check(prefix: 'libgimp2.0-doc', release: '3.1', reference: '2.2.6-1sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
