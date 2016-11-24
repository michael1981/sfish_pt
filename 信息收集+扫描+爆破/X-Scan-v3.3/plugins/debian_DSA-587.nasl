# This script was automatically generated from the dsa-587
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15685);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "587");
 script_cve_id("CVE-2004-0964");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-587 security update');
 script_set_attribute(attribute: 'description', value:
'Luigi Auriemma discovered a buffer overflow condition in the playlist
module of freeamp which could lead to arbitrary code execution.
Recent versions of freeamp were renamed into zinf.
For the stable distribution (woody) this problem has been fixed in
version 2.1.1.0-4woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-587');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your freeamp packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA587] DSA-587-1 freeamp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-587-1 freeamp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'freeamp', release: '3.0', reference: '2.1.1.0-4woody2');
deb_check(prefix: 'freeamp-doc', release: '3.0', reference: '2.1.1.0-4woody2');
deb_check(prefix: 'freeamp-extras', release: '3.0', reference: '2.1.1.0-4woody2');
deb_check(prefix: 'libfreeamp-alsa', release: '3.0', reference: '2.1.1.0-4woody2');
deb_check(prefix: 'libfreeamp-esound', release: '3.0', reference: '2.1.1.0-4woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
