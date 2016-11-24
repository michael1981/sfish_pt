# This script was automatically generated from the dsa-200
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15037);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "200");
 script_cve_id("CVE-2002-1318");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-200 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Langasek found an exploitable bug in the password handling
code in samba: when converting from DOS code-page to little endian
UCS2 unicode a buffer length was not checked and a buffer could
be overflowed. There is no known exploit for this, but an upgrade
is strongly recommended.
This problem has been fixed in version 2.2.3a-12 of the Debian
samba packages and upstream version 2.2.7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-200');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-200
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA200] DSA-200-1 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-200-1 samba");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-smbpass', release: '3.0', reference: '2.2.3a-12');
deb_check(prefix: 'libsmbclient', release: '3.0', reference: '2.2.3a-12');
deb_check(prefix: 'libsmbclient-dev', release: '3.0', reference: '2.2.3a-12');
deb_check(prefix: 'samba', release: '3.0', reference: '2.2.3a-12');
deb_check(prefix: 'samba-common', release: '3.0', reference: '2.2.3a-12');
deb_check(prefix: 'samba-doc', release: '3.0', reference: '2.2.3a-12');
deb_check(prefix: 'smbclient', release: '3.0', reference: '2.2.3a-12');
deb_check(prefix: 'smbfs', release: '3.0', reference: '2.2.3a-12');
deb_check(prefix: 'swat', release: '3.0', reference: '2.2.3a-12');
deb_check(prefix: 'winbind', release: '3.0', reference: '2.2.3a-12');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
