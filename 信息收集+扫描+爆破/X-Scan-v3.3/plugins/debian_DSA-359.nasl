# This script was automatically generated from the dsa-359
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15196);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "359");
 script_cve_id("CVE-2003-0630");
 script_bugtraq_id(8322);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-359 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp discovered multiple buffer overflows in atari800, an Atari
emulator.  In order to directly access graphics hardware, one of the
affected programs is setuid root.  A local attacker could exploit this
vulnerability to gain root privileges.
For the current stable distribution (woody) this problem has been fixed
in version 1.2.2-1woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-359');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-359
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA359] DSA-359-1 atari800");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-359-1 atari800");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'atari800', release: '3.0', reference: '1.2.2-1woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
