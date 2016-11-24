# This script was automatically generated from the dsa-859
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19967);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "859");
 script_cve_id("CVE-2005-3178");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-859 security update');
 script_set_attribute(attribute: 'description', value:
'Ariel Berkman discovered several buffer overflows in xloadimage, which
are also present in xli, a command line utility for viewing images in
X11, and could be exploited via large image titles and cause the
execution of arbitrary code.
For the old stable distribution (woody) these problems have been fixed in
version 1.17.0-11woody2.
For the stable distribution (sarge) these problems have been fixed in
version 1.17.0-18sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-859');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xli package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA859] DSA-859-1 xli");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-859-1 xli");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xli', release: '3.0', reference: '1.17.0-11woody2');
deb_check(prefix: 'xli', release: '3.1', reference: '1.17.0-18sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
