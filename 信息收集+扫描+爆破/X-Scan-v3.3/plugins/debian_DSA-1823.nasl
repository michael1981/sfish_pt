# This script was automatically generated from the dsa-1823
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(39568);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1823");
 script_cve_id("CVE-2009-1886", "CVE-2009-1888");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1823 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Samba, a SMB/CIFS file,
print, and login server. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2009-1886
    The smbclient utility contains a formatstring vulnerability where
    commands dealing with file names treat user input as format strings
    to asprintf.
CVE-2009-1888
    In  the smbd daemon, if a user is trying to modify an access control
    list (ACL) and is denied permission, this deny may be overridden if
    the parameter "dos filemode" is set to "yes" in the smb.conf and the
    user already has write access to the file.
The old stable distribution (etch) is not affected by these problems.
For the stable distribution (lenny), these problems have been fixed in
version 3.2.5-4lenny6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1823');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your samba package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1823] DSA-1823-1 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1823-1 samba");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-smbpass', release: '5.0', reference: '3.2.5-4lenny6');
deb_check(prefix: 'libsmbclient', release: '5.0', reference: '3.2.5-4lenny6');
deb_check(prefix: 'libsmbclient-dev', release: '5.0', reference: '3.2.5-4lenny6');
deb_check(prefix: 'libwbclient0', release: '5.0', reference: '3.2.5-4lenny6');
deb_check(prefix: 'samba', release: '5.0', reference: '3.2.5-4lenny6');
deb_check(prefix: 'samba-common', release: '5.0', reference: '3.2.5-4lenny6');
deb_check(prefix: 'samba-dbg', release: '5.0', reference: '3.2.5-4lenny6');
deb_check(prefix: 'samba-doc', release: '5.0', reference: '3.2.5-4lenny6');
deb_check(prefix: 'samba-doc-pdf', release: '5.0', reference: '3.2.5-4lenny6');
deb_check(prefix: 'samba-tools', release: '5.0', reference: '3.2.5-4lenny6');
deb_check(prefix: 'smbclient', release: '5.0', reference: '3.2.5-4lenny6');
deb_check(prefix: 'smbfs', release: '5.0', reference: '3.2.5-4lenny6');
deb_check(prefix: 'swat', release: '5.0', reference: '3.2.5-4lenny6');
deb_check(prefix: 'winbind', release: '5.0', reference: '3.2.5-4lenny6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
