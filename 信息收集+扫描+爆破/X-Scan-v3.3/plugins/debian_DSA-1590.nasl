# This script was automatically generated from the dsa-1590
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32482);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1590");
 script_cve_id("CVE-2008-1105");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1590 security update');
 script_set_attribute(attribute: 'description', value:
'Alin Rad Pop discovered that Samba contained a buffer overflow condition
when processing certain responses received while acting as a client,
leading to arbitrary code execution (CVE-2008-1105).
For the stable distribution (etch), this problem has been fixed in version 
3.0.24-6etch10.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1590');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your samba packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1590] DSA-1590-1 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1590-1 samba");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-smbpass', release: '4.0', reference: '3.0.24-6etch10');
deb_check(prefix: 'libsmbclient', release: '4.0', reference: '3.0.24-6etch10');
deb_check(prefix: 'libsmbclient-dev', release: '4.0', reference: '3.0.24-6etch10');
deb_check(prefix: 'python-samba', release: '4.0', reference: '3.0.24-6etch10');
deb_check(prefix: 'samba', release: '4.0', reference: '3.0.24-6etch10');
deb_check(prefix: 'samba-common', release: '4.0', reference: '3.0.24-6etch10');
deb_check(prefix: 'samba-dbg', release: '4.0', reference: '3.0.24-6etch10');
deb_check(prefix: 'samba-doc', release: '4.0', reference: '3.0.24-6etch10');
deb_check(prefix: 'samba-doc-pdf', release: '4.0', reference: '3.0.24-6etch10');
deb_check(prefix: 'smbclient', release: '4.0', reference: '3.0.24-6etch10');
deb_check(prefix: 'smbfs', release: '4.0', reference: '3.0.24-6etch10');
deb_check(prefix: 'swat', release: '4.0', reference: '3.0.24-6etch10');
deb_check(prefix: 'winbind', release: '4.0', reference: '3.0.24-6etch10');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
