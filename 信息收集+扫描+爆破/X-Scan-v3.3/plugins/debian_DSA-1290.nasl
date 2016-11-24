# This script was automatically generated from the dsa-1290
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25227);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1290");
 script_cve_id("CVE-2007-1262");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1290 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the webmail package Squirrelmail performs
insufficient sanitising inside the HTML filter, which allows the
injection of arbitrary web script code during the display of HTML
email messages.
For the oldstable distribution (sarge) this problem has been fixed in
version 2:1.4.4-11.
For the stable distribution (etch) this problem has been fixed in
version 2:1.4.9a-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1290');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your squirrelmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1290] DSA-1290-1 squirrelmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1290-1 squirrelmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squirrelmail', release: '3.1', reference: '1.4.4-11');
deb_check(prefix: 'squirrelmail', release: '4.0', reference: '1.4.9a-2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
