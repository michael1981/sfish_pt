# This script was automatically generated from the dsa-969
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22835);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "969");
 script_cve_id("CVE-2005-4532", "CVE-2005-4533");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-969 security update');
 script_set_attribute(attribute: 'description', value:
'Max Vozeler discovered a vulnerability in scponly, a utility to
restrict user commands to scp and sftp, that could lead to the
execution of arbitrary commands as root.  The system is only vulnerable
if the program scponlyc is installed setuid root and if regular users
have shell access to the machine.
The old stable distribution (woody) does not contain an scponly package.
For the stable distribution (sarge) this problem has been fixed in
version 4.0-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-969');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your scponly package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA969] DSA-969-1 scponly");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-969-1 scponly");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'scponly', release: '3.1', reference: '4.0-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
