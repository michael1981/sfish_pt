# This script was automatically generated from the dsa-664
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16300);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "664");
 script_cve_id("CVE-1999-1572");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-664 security update');
 script_set_attribute(attribute: 'description', value:
'It has been discovered, that cpio, a program to manage archives of
files, creates output files with -O and -F with broken permissions due
to a reset zero umask which allows local users to read or overwrite
those files.
For the stable distribution (woody) this problem has been fixed in
version 2.4.2-39woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-664');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cpio package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA664] DSA-664-1 cpio");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-664-1 cpio");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cpio', release: '3.0', reference: '2.4.2-39woody1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
