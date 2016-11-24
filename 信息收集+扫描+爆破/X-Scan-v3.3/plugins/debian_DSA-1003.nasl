# This script was automatically generated from the dsa-1003
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22545);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1003");
 script_cve_id("CVE-2005-2240");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1003 security update');
 script_set_attribute(attribute: 'description', value:
'Eric Romang discovered that xpvm, a graphical console and monitor for
PVM, creates a temporary file that allows local attackers to create or
overwrite arbitrary files with the privileges of the user running
xpvm.
For the old stable distribution (woody) this problem has been fixed in
version 1.2.5-7.2woody1.
For the stable distribution (sarge) this problem has been fixed in
version 1.2.5-7.3sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1003');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xpvm package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1003] DSA-1003-1 xpvm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1003-1 xpvm");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xpvm', release: '3.0', reference: '1.2.5-7.2woody1');
deb_check(prefix: 'xpvm', release: '3.1', reference: '1.2.5-7.3sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
