# This script was automatically generated from the dsa-1267
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24834);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1267");
 script_cve_id("CVE-2007-1343");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1267 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that WebCalendar, a PHP-based calendar application,
insufficiently protects an internal variable, which allows remote file
inclusion.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.45-4sarge6.
The upcoming stable distribution (etch) no longer contains webcalendar
packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1267');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your webcalendar package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1267] DSA-1267-1 webcalendar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1267-1 webcalendar");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'webcalendar', release: '3.1', reference: '0.9.45-4sarge6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
