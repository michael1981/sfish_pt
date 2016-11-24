# This script was automatically generated from the dsa-095
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14932);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "095");
 script_cve_id("CVE-2001-1203");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-095 security update');
 script_set_attribute(attribute: 'description', value:
'The package \'gpm\' contains the gpm-root program, which can be used to
create mouse-activated menus on the console.
Among other problems, the gpm-root program contains a format string
vulnerability, which allows an attacker to gain root privileges.

This has been fixed in version 1.17.8-18.1, and we recommend that you upgrade
your 1.17.8-18 package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-095');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-095
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA095] DSA-095-1 gpm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-095-1 gpm");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gpm', release: '2.2', reference: '1.17.8-18.1');
deb_check(prefix: 'libgpm1', release: '2.2', reference: '1.17.8-18.1');
deb_check(prefix: 'libgpm1-altdev', release: '2.2', reference: '1.17.8-18.1');
deb_check(prefix: 'libgpmg1', release: '2.2', reference: '1.17.8-18.1');
deb_check(prefix: 'libgpmg1-dev', release: '2.2', reference: '1.17.8-18.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
