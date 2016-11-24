# This script was automatically generated from the dsa-110
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14947);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "110");
 script_cve_id("CVE-2002-0063");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-110 security update');
 script_set_attribute(attribute: 'description', value:
'The authors of CUPS, the Common UNIX Printing System, have found a
potential buffer overflow bug in the code of the CUPS daemon where it
reads the names of attributes.  This affects all versions of CUPS.
This problem has been fixed in version 1.0.4-10 for the stable Debian
distribution and version 1.1.13-2 for the current testing/unstable
distribution.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-110');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your CUPS packages immediately if you
have them installed.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA110] DSA-110-1 cups");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-110-1 cups");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cupsys', release: '2.2', reference: '1.0.4-10');
deb_check(prefix: 'cupsys-bsd', release: '2.2', reference: '1.0.4-10');
deb_check(prefix: 'libcupsys1', release: '2.2', reference: '1.0.4-10');
deb_check(prefix: 'libcupsys1-dev', release: '2.2', reference: '1.0.4-10');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
