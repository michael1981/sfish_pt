# This script was automatically generated from the dsa-408
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15245);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "408");
 script_cve_id("CVE-2003-0972");
 script_bugtraq_id(9117);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-408 security update');
 script_set_attribute(attribute: 'description', value:
'Timo Sirainen reported a vulnerability in screen, a terminal
multiplexor with VT100/ANSI terminal emulation, that can lead an
attacker to gain group utmp privileges.
For the stable distribution (woody) this problem has been fixed in
version 3.9.11-5woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-408');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your screen package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA408] DSA-408-1 screen");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-408-1 screen");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'screen', release: '3.0', reference: '3.9.11-5woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
