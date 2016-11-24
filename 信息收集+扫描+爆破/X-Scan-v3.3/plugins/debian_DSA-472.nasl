# This script was automatically generated from the dsa-472
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15309);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "472");
 script_cve_id("CVE-2003-0648");
 script_bugtraq_id(10041);
 script_xref(name: "CERT", value: "354838");
 script_xref(name: "CERT", value: "900964");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-472 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp and Jaguar discovered a number of buffer overflow
vulnerabilities in vfte, a version of the fte editor which runs on the
Linux console, found in the package fte-console.  This program is
setuid root in order to perform certain types of low-level operations
on the console.
Due to these bugs, setuid privilege has been removed from vfte, making
it only usable by root.  We recommend using the terminal version (in
the fte-terminal package) instead, which runs on any capable terminal
including the Linux console.
For the stable distribution (woody) these problems have been fixed in
version 0.49.13-15woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-472');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-472
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA472] DSA-472-1 fte");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-472-1 fte");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fte', release: '3.0', reference: '0.49.13-15woody1');
deb_check(prefix: 'fte-console', release: '3.0', reference: '0.49.13-15woody1');
deb_check(prefix: 'fte-docs', release: '3.0', reference: '0.49.13-15woody1');
deb_check(prefix: 'fte-terminal', release: '3.0', reference: '0.49.13-15woody1');
deb_check(prefix: 'fte-xwindow', release: '3.0', reference: '0.49.13-15woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
