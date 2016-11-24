# This script was automatically generated from the dsa-609
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15961);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "609");
 script_cve_id("CVE-2004-1076");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-609 security update');
 script_set_attribute(attribute: 'description', value:
'Adam Zabrocki discovered multiple buffer overflows in atari800, an
Atari emulator.  In order to directly access graphics hardware, one of
the affected programs is installed setuid root.  A local attacker
could exploit this vulnerability to gain root privileges.
For the stable distribution (woody) these problems have been fixed in
version 1.2.2-1woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-609');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your atari800 package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA609] DSA-609-1 atari800");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-609-1 atari800");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'atari800', release: '3.0', reference: '1.2.2-1woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
