# This script was automatically generated from the dsa-701
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(17664);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "701");
 script_cve_id("CVE-2004-1154");
 script_xref(name: "CERT", value: "226184");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-701 security update');
 script_set_attribute(attribute: 'description', value:
'It has been discovered that the last security update for Samba, a
LanManager like file and printer server for GNU/Linux and Unix-like
systems caused the daemon to crash upon reload. This has been fixed.
For reference below is the original advisory text:
Greg MacManus discovered an integer overflow in the smb daemon from
Samba, a LanManager like file and printer server for GNU/Linux and
Unix-like systems.  Requesting a very large number of access control
descriptors from the server could exploit the integer overflow, which
may result in a buffer overflow which could lead to the execution of
arbitrary code with root privileges.  Upstream developers have
discovered more possible integer overflows that are fixed with this
update as well.
For the stable distribution (woody) these problems have been fixed in
version 2.2.3a-15.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-701');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your samba packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA701] DSA-701-2 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-701-2 samba");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-smbpass', release: '3.0', reference: '2.2.3a-15');
deb_check(prefix: 'libsmbclient', release: '3.0', reference: '2.2.3a-15');
deb_check(prefix: 'libsmbclient-dev', release: '3.0', reference: '2.2.3a-15');
deb_check(prefix: 'samba', release: '3.0', reference: '2.2.3a-15');
deb_check(prefix: 'samba-common', release: '3.0', reference: '2.2.3a-15');
deb_check(prefix: 'samba-doc', release: '3.0', reference: '2.2.3a-15');
deb_check(prefix: 'smbclient', release: '3.0', reference: '2.2.3a-15');
deb_check(prefix: 'smbfs', release: '3.0', reference: '2.2.3a-15');
deb_check(prefix: 'swat', release: '3.0', reference: '2.2.3a-15');
deb_check(prefix: 'winbind', release: '3.0', reference: '2.2.3a-15');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
