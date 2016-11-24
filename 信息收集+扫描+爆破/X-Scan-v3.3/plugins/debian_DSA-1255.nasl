# This script was automatically generated from the dsa-1255
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24294);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1255");
 script_cve_id("CVE-2007-0235");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1255 security update');
 script_set_attribute(attribute: 'description', value:
'Liu Qishuai discovered that the GNOME gtop library performs insufficient
sanitising when parsing the system\'s /proc table, which may lead to
the execution of arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 2.6.0-4sarge1.
For the upcoming stable distribution (etch) this problem has been
fixed in version 2.14.4-3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1255');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libgtop2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1255] DSA-1255-1 libgtop2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1255-1 libgtop2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libgtop2-2', release: '3.1', reference: '2.6.0-4sarge1');
deb_check(prefix: 'libgtop2-daemon', release: '3.1', reference: '2.6.0-4sarge1');
deb_check(prefix: 'libgtop2-dev', release: '3.1', reference: '2.6.0-4sarge1');
deb_check(prefix: 'libgtop2', release: '4.0', reference: '2.14.4-3');
deb_check(prefix: 'libgtop2', release: '3.1', reference: '2.6.0-4sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
