# This script was automatically generated from the dsa-1716
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35567);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1716");
 script_cve_id("CVE-2008-4770");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1716 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that xvnc4viewer, a virtual network computing client
software for X, is prone to an integer overflow via a malicious
encoding value that could lead to arbitrary code execution.
For the stable distribution (etch) this problem has been fixed in
version 4.1.1+X4.3.0-21+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1716');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your vnc4 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1716] DSA-1716-1 vnc4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1716-1 vnc4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'vnc4-common', release: '4.0', reference: '4.1.1+X4.3.0-21+etch1');
deb_check(prefix: 'vnc4server', release: '4.0', reference: '4.1.1+X4.3.0-21+etch1');
deb_check(prefix: 'xvnc4viewer', release: '4.0', reference: '4.1.1+X4.3.0-21+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
