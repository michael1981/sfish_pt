# This script was automatically generated from the dsa-385
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15222);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "385");
 script_cve_id("CVE-2003-0783");
 script_bugtraq_id(8656);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-385 security update');
 script_set_attribute(attribute: 'description', value:
'Jens Steube reported a pair of buffer overflow vulnerabilities in
hztty, a program to translate Chinese character encodings in a
terminal session.  These vulnerabilities could be exploited by a local
attacker to gain root privileges on a system where hztty is installed.
Additionally, hztty had been incorrectly installed setuid root, when
it only requires the privileges of group utmp.  This has also been
corrected in this update.
For the stable distribution (woody) this problem has been fixed in
version 2.0-5.2woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-385');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-385
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA385] DSA-385-1 hztty");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-385-1 hztty");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'hztty', release: '3.0', reference: '2.0-5.2woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
