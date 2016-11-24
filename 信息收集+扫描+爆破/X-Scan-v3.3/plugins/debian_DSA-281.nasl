# This script was automatically generated from the dsa-281
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15118);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "281");
 script_cve_id("CVE-2003-0203");
 script_bugtraq_id(6921);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-281 security update');
 script_set_attribute(attribute: 'description', value:
'Knud Erik Højgaard discovered a vulnerability in moxftp (and xftp
respectively), an Athena X interface to FTP.  Insufficient bounds
checking could lead to execution of arbitrary code, provided by a
malicious FTP server.   Erik Tews fixed this.
For the stable distribution (woody) this problem has been fixed in
version 2.2-18.1.
For the old stable distribution (potato) this problem has been fixed
in version 2.2-13.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-281');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xftp package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA281] DSA-281-1 moxftp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-281-1 moxftp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xftp', release: '2.2', reference: '2.2-13.1');
deb_check(prefix: 'xftp', release: '3.0', reference: '2.2-18.1');
deb_check(prefix: 'moxftp', release: '2.2', reference: '2.2-13.1');
deb_check(prefix: 'moxftp', release: '3.0', reference: '2.2-18.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
