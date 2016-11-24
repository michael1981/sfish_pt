# This script was automatically generated from the dsa-280
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15117);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "280");
 script_cve_id("CVE-2003-0196", "CVE-2003-0201");
 script_bugtraq_id(7294, 7295);
 script_xref(name: "CERT", value: "267873");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-280 security update');
 script_set_attribute(attribute: 'description', value:
'Digital Defense, Inc. has alerted the Samba Team to a serious
vulnerability in Samba, a LanManager-like file and printer server for Unix.
This vulnerability can lead to an anonymous user gaining root access
on a Samba serving system.  An exploit for this problem is already
circulating and in use.
Since the packages for potato are quite old it is likely that they
contain more security-relevant bugs that we don\'t know of.  You are
therefore advised to upgrade your systems running Samba to woody
soon.
Unofficial backported packages from the Samba maintainers for version
2.2.8 of Samba for woody are available at
~peloy and
~vorlon.
For the stable distribution (woody) this problem has been fixed in
version 2.2.3a-12.3.
For the old stable distribution (potato) this problem has been fixed in
version 2.0.7-5.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-280');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Samba packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA280] DSA-280-1 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-280-1 samba");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'samba', release: '2.2', reference: '2.0.7-5.1');
deb_check(prefix: 'samba-common', release: '2.2', reference: '2.0.7-5.1');
deb_check(prefix: 'samba-doc', release: '2.2', reference: '2.0.7-5.1');
deb_check(prefix: 'smbclient', release: '2.2', reference: '2.0.7-5.1');
deb_check(prefix: 'smbfs', release: '2.2', reference: '2.0.7-5.1');
deb_check(prefix: 'swat', release: '2.2', reference: '2.0.7-5.1');
deb_check(prefix: 'libpam-smbpass', release: '3.0', reference: '2.2.3a-12.3');
deb_check(prefix: 'libsmbclient', release: '3.0', reference: '2.2.3a-12.3');
deb_check(prefix: 'libsmbclient-dev', release: '3.0', reference: '2.2.3a-12.3');
deb_check(prefix: 'samba', release: '3.0', reference: '2.2.3a-12.3');
deb_check(prefix: 'samba-common', release: '3.0', reference: '2.2.3a-12.3');
deb_check(prefix: 'samba-doc', release: '3.0', reference: '2.2.3a-12.3');
deb_check(prefix: 'smbclient', release: '3.0', reference: '2.2.3a-12.3');
deb_check(prefix: 'smbfs', release: '3.0', reference: '2.2.3a-12.3');
deb_check(prefix: 'swat', release: '3.0', reference: '2.2.3a-12.3');
deb_check(prefix: 'winbind', release: '3.0', reference: '2.2.3a-12.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
