# This script was automatically generated from the dsa-600
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15690);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "600");
 script_cve_id("CVE-2004-0815");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-600 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability has been discovered in samba, a commonly used
LanManager-like file and printer server for Unix.  A remote attacker
may be able to gain access to files which exist outside of the share\'s
defined path.  Such files must still be readable by the account used
for the connection, though.
For the stable distribution (woody) this problem has been fixed in
version 2.2.3a-14.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-600');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your samba packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA600] DSA-600-1 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-600-1 samba");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-smbpass', release: '3.0', reference: '2.2.3a-14.1');
deb_check(prefix: 'libsmbclient', release: '3.0', reference: '2.2.3a-14.1');
deb_check(prefix: 'libsmbclient-dev', release: '3.0', reference: '2.2.3a-14.1');
deb_check(prefix: 'samba', release: '3.0', reference: '2.2.3a-14.1');
deb_check(prefix: 'samba-common', release: '3.0', reference: '2.2.3a-14.1');
deb_check(prefix: 'samba-doc', release: '3.0', reference: '2.2.3a-14.1');
deb_check(prefix: 'smbclient', release: '3.0', reference: '2.2.3a-14.1');
deb_check(prefix: 'smbfs', release: '3.0', reference: '2.2.3a-14.1');
deb_check(prefix: 'swat', release: '3.0', reference: '2.2.3a-14.1');
deb_check(prefix: 'winbind', release: '3.0', reference: '2.2.3a-14.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
