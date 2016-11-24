# This script was automatically generated from the dsa-1518
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31589);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1518");
 script_cve_id("CVE-2007-4656");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1518 security update');
 script_set_attribute(attribute: 'description', value:
'Micha Lenk discovered that backup-manager, a command-line backup tool,
sends the password as a command line argument when calling a FTP client,
which may allow a local attacker to read this password (which provides
access to all backed-up files) from the process listing.
For the old stable distribution (sarge), this problem has been fixed in
version 0.5.7-1sarge2.
For the stable distribution (etch), this problem has been fixed in version
0.7.5-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1518');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your backup-manager package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1518] DSA-1518-1 backup-manager");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1518-1 backup-manager");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'backup-manager', release: '3.1', reference: '0.5.7-1sarge2');
deb_check(prefix: 'backup-manager', release: '4.0', reference: '0.7.5-4');
deb_check(prefix: 'backup-manager-doc', release: '4.0', reference: '0.7.5-4');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
