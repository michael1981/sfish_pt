# This script was automatically generated from the dsa-1084
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22626);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1084");
 script_cve_id("CVE-2006-1515");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1084 security update');
 script_set_attribute(attribute: 'description', value:
'Niko Tyni discovered a buffer overflow in the processing of network
data in typespeed, a game for testing and improving typing speed, which
could lead to the execution of arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 0.4.1-2.4.
For the stable distribution (sarge) this problem has been fixed in
version 0.4.4-8sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1084');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your typespeed packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1084] DSA-1084-1 typespeed");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1084-1 typespeed");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'typespeed', release: '3.0', reference: '0.4.1-2.4');
deb_check(prefix: 'typespeed', release: '3.1', reference: '0.4.4-8sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
