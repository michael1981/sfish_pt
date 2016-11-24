# This script was automatically generated from the dsa-672
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16346);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "672");
 script_cve_id("CVE-2005-0076");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-672 security update');
 script_set_attribute(attribute: 'description', value:
'Erik Sjölund discovered that programs linked against xview are
vulnerable to a number of buffer overflows in the XView library.  When
the overflow is triggered in a program which is installed setuid root
a malicious user could perhaps execute arbitrary code as privileged
user.
For the stable distribution (woody) these problems have been fixed in
version 3.2p1.4-16woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-672');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xview packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA672] DSA-672-1 xview");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-672-1 xview");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'olvwm', release: '3.0', reference: '4.4.3.2p1.4-16woody2');
deb_check(prefix: 'olwm', release: '3.0', reference: '3.2p1.4-16woody2');
deb_check(prefix: 'xview-clients', release: '3.0', reference: '3.2p1.4-16woody2');
deb_check(prefix: 'xview-examples', release: '3.0', reference: '3.2p1.4-16woody2');
deb_check(prefix: 'xviewg', release: '3.0', reference: '3.2p1.4-16woody2');
deb_check(prefix: 'xviewg-dev', release: '3.0', reference: '3.2p1.4-16woody2');
deb_check(prefix: 'xview', release: '3.0', reference: '3.2p1.4-16woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
