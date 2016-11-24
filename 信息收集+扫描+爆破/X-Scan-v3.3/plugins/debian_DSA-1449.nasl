# This script was automatically generated from the dsa-1449
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29858);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1449");
 script_cve_id("CVE-2007-5191");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1449 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that loop-aes-utils, tools for mounting and manipulating
filesystems, didn\'t drop privileged user and group permissions in the correct order
in the mount and umount commands.  This could potentially allow a local
user to gain additional privileges.
For the old stable distribution (sarge), this problem has been fixed in
version 2.12p-4sarge2.
For the stable distribution (etch), this problem has been fixed in version
2.12r-15+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1449');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your loop-aes-utils package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1449] DSA-1449-1 loop-aes-utils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1449-1 loop-aes-utils");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'loop-aes-utils', release: '3.1', reference: '2.12p-4sarge2');
deb_check(prefix: 'loop-aes-utils', release: '4.0', reference: '2.12r-15+etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
