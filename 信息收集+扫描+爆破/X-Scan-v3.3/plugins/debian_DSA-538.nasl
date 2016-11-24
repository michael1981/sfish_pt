# This script was automatically generated from the dsa-538
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15375);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "538");
 script_cve_id("CVE-2004-0792");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-538 security update');
 script_set_attribute(attribute: 'description', value:
'The rsync developers have discovered a security related problem in
rsync, a fast remote file copy program, which offers an attacker to
access files outside of the defined directory.  To exploit this
path-sanitizing bug, rsync has to run in daemon mode with the chroot
option being disabled.  It does not affect the normal send/receive
filenames that specify what files should be transferred.  It does
affect certain option paths that cause auxiliary files to be read or
written.
For the stable distribution (woody) this problem has been fixed in
version 2.5.5-0.6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-538');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your rsync package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA538] DSA-538-1 rsync");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-538-1 rsync");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'rsync', release: '3.0', reference: '2.5.5-0.6');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
