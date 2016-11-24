# This script was automatically generated from the dsa-1545
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31951);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1545");
 script_cve_id("CVE-2008-1720");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1545 security update');
 script_set_attribute(attribute: 'description', value:
'Sebastian Krahmer discovered that an integer overflow in rsync\'s code
for handling extended attributes may lead to arbitrary code execution.
For the stable distribution (etch), this problem has been fixed in
version 2.6.9-2etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1545');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your rsync package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1545] DSA-1545-1 rsync");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1545-1 rsync");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'rsync', release: '4.0', reference: '2.6.9-2etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
