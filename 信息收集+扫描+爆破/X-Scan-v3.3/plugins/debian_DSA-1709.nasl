# This script was automatically generated from the dsa-1709
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35431);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1709");
 script_cve_id("CVE-2008-5394");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1709 security update');
 script_set_attribute(attribute: 'description', value:
'Paul Szabo discovered that login, the system login tool, did not
correctly handle symlinks while setting up tty permissions. If a local
attacker were able to gain control of the system utmp file, they could
cause login to change the ownership and permissions on arbitrary files,
leading to a root privilege escalation.
For the stable distribution (etch), this problem has been fixed in
version 4.0.18.1-7+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1709');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your shadow package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1709] DSA-1709-1 shadow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1709-1 shadow");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'login', release: '4.0', reference: '4.0.18.1-7+etch1');
deb_check(prefix: 'passwd', release: '4.0', reference: '4.0.18.1-7+etch1');
deb_check(prefix: 'shadow', release: '4.0', reference: '4.0.18.1-7+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
