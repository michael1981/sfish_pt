# This script was automatically generated from the dsa-1056
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22598);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1056");
 script_cve_id("CVE-2006-2247");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1056 security update');
 script_set_attribute(attribute: 'description', value:
'David Maciejak noticed that webcalendar, a PHP-based multi-user
calendar, returns different error messages on login attempts for an
invalid password and a non-existing user, allowing remote attackers to
gain information about valid usernames.
The old stable distribution (woody) does not contain a webcalendar package.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.45-4sarge4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1056');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your webcalendar package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1056] DSA-1056-1 webcalendar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1056-1 webcalendar");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'webcalendar', release: '3.1', reference: '0.9.45-4sarge4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
