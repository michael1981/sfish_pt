# This script was automatically generated from the dsa-463
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15300);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "463");
 script_cve_id("CVE-2004-0186");
 script_bugtraq_id(9619);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-463 security update');
 script_set_attribute(attribute: 'description', value:
'Samba, a LanManager-like file and printer server for Unix, was found
to contain a vulnerability whereby a local user could use the "smbmnt"
utility, which is setuid root, to mount a file share from a remote
server which contained setuid programs under the control of the user.
These programs could then be executed to gain privileges on the local
system.
For the current stable distribution (woody) this problem has been
fixed in version 2.2.3a-13.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-463');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-463
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA463] DSA-463-1 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-463-1 samba");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-smbpass', release: '3.0', reference: '2.2.3a-13');
deb_check(prefix: 'libsmbclient', release: '3.0', reference: '2.2.3a-13');
deb_check(prefix: 'libsmbclient-dev', release: '3.0', reference: '2.2.3a-13');
deb_check(prefix: 'samba', release: '3.0', reference: '2.2.3a-13');
deb_check(prefix: 'samba-common', release: '3.0', reference: '2.2.3a-13');
deb_check(prefix: 'samba-doc', release: '3.0', reference: '2.2.3a-13');
deb_check(prefix: 'smbclient', release: '3.0', reference: '2.2.3a-13');
deb_check(prefix: 'smbfs', release: '3.0', reference: '2.2.3a-13');
deb_check(prefix: 'swat', release: '3.0', reference: '2.2.3a-13');
deb_check(prefix: 'winbind', release: '3.0', reference: '2.2.3a-13');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
