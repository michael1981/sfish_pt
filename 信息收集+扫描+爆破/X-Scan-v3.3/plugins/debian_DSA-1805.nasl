# This script was automatically generated from the dsa-1805
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38878);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1805");
 script_cve_id("CVE-2009-1373", "CVE-2009-1375", "CVE-2009-1376");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1805 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Pidgin, a graphical
multi-protocol instant messaging client. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2009-1373
    A buffer overflow in the Jabber file transfer code may lead to
    denial of service or the execution of arbitrary code.
CVE-2009-1375
    Memory corruption in an internal library may lead to denial of
    service.
CVE-2009-1376
    The patch provided for the security issue tracked as CVE-2008-2927
    - integer overflows in the MSN protocol handler - was found to be
    incomplete.
The old stable distribution (etch) is affected under the source package
name gaim. However, due to build problems the updated packages couldn\'t
be released along with the stable version. It will be released once the
build problem is resolved.
For the stable distribution (lenny), these problems have been fixed in
version 2.4.3-4lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1805');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your pidgin packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1805] DSA-1805-1 pidgin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1805-1 pidgin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'finch', release: '5.0', reference: '2.4.3-4lenny2');
deb_check(prefix: 'finch-dev', release: '5.0', reference: '2.4.3-4lenny2');
deb_check(prefix: 'libpurple-bin', release: '5.0', reference: '2.4.3-4lenny2');
deb_check(prefix: 'libpurple-dev', release: '5.0', reference: '2.4.3-4lenny2');
deb_check(prefix: 'libpurple0', release: '5.0', reference: '2.4.3-4lenny2');
deb_check(prefix: 'pidgin', release: '5.0', reference: '2.4.3-4lenny2');
deb_check(prefix: 'pidgin-data', release: '5.0', reference: '2.4.3-4lenny2');
deb_check(prefix: 'pidgin-dbg', release: '5.0', reference: '2.4.3-4lenny2');
deb_check(prefix: 'pidgin-dev', release: '5.0', reference: '2.4.3-4lenny2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
