# This script was automatically generated from the dsa-650
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16234);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "650");
 script_cve_id("CVE-2005-0015");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-650 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar discovered that due to missing input sanitising in
diatheke, a CGI script for making and browsing a bible website, it is
possible to execute arbitrary commands via a specially crafted URL.
For the stable distribution (woody) this problem has been fixed in
version 1.5.3-3woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-650');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your diatheke package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA650] DSA-650-1 sword");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-650-1 sword");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'diatheke', release: '3.0', reference: '1.5.3-3woody2');
deb_check(prefix: 'libsword-dev', release: '3.0', reference: '1.5.3-3woody2');
deb_check(prefix: 'libsword-runtime', release: '3.0', reference: '1.5.3-3woody2');
deb_check(prefix: 'libsword1', release: '3.0', reference: '1.5.3-3woody2');
deb_check(prefix: 'sword', release: '3.0', reference: '1.5.3-3woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
