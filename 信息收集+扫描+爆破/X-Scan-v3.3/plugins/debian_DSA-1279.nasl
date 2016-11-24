# This script was automatically generated from the dsa-1279
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25096);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1279");
 script_cve_id("CVE-2006-6669");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1279 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that WebCalendar, a PHP-based calendar application,
performs insufficient sanitising in the exports handler, which allows
injection of web script.
For the old stable distribution (sarge) this problem has been fixed in
version 0.9.45-4sarge7.
The stable distribution (etch) no longer contains WebCalendar packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1279');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your webcalendar package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1279] DSA-1279-1 webcalendar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1279-1 webcalendar");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'webcalendar', release: '3.1', reference: '0.9.45-4sarge7');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
