# This script was automatically generated from the dsa-976
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22842);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "976");
 script_cve_id("CVE-2006-0224");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-976 security update');
 script_set_attribute(attribute: 'description', value:
'Johnny Mast discovered a buffer overflow in libast, the library of
assorted spiffy things, that can lead to the execution of arbitrary
code.  This library is used by eterm which is installed setgid uid
which leads to a vulnerability to alter the utmp file.
For the old stable distribution (woody) this problem has been fixed in
version 0.4-3woody2.
For the stable distribution (sarge) this problem has been fixed in
version 0.6-0pre2003010606sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-976');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libast packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA976] DSA-976-1 libast");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-976-1 libast");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libast1', release: '3.0', reference: '0.4-3woody2');
deb_check(prefix: 'libast1-dev', release: '3.0', reference: '0.4-3woody2');
deb_check(prefix: 'libast2', release: '3.1', reference: '0.6-0pre2003010606sarge1');
deb_check(prefix: 'libast2-dev', release: '3.1', reference: '0.6-0pre2003010606sarge1');
deb_check(prefix: 'libast,', release: '3.1', reference: '0.6-0pre2003010606sarge1');
deb_check(prefix: 'libast,', release: '3.0', reference: '0.4-3woody2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
