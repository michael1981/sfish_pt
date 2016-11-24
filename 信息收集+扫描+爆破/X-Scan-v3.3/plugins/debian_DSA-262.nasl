# This script was automatically generated from the dsa-262
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15099);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "262");
 script_cve_id("CVE-2003-0085", "CVE-2003-0086");
 script_bugtraq_id(7106, 7107);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-262 security update');
 script_set_attribute(attribute: 'description', value:
'Sebastian Krahmer of the SuSE security audit team found two problems
in samba, a popular SMB/CIFS implementation. The problems are:
Both problems have been fixed in upstream version 2.2.8, and version
2.2.3a-12.1 of package for Debian GNU/Linux 3.0/woody.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-262');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-262
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA262] DSA-262-1 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-262-1 samba");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-smbpass', release: '3.0', reference: '2.2.3a-12.1');
deb_check(prefix: 'libsmbclient', release: '3.0', reference: '2.2.3a-12.1');
deb_check(prefix: 'libsmbclient-dev', release: '3.0', reference: '2.2.3a-12.1');
deb_check(prefix: 'samba', release: '3.0', reference: '2.2.3a-12.1');
deb_check(prefix: 'samba-common', release: '3.0', reference: '2.2.3a-12.1');
deb_check(prefix: 'samba-doc', release: '3.0', reference: '2.2.3a-12.1');
deb_check(prefix: 'smbclient', release: '3.0', reference: '2.2.3a-12.1');
deb_check(prefix: 'smbfs', release: '3.0', reference: '2.2.3a-12.1');
deb_check(prefix: 'swat', release: '3.0', reference: '2.2.3a-12.1');
deb_check(prefix: 'winbind', release: '3.0', reference: '2.2.3a-12.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
