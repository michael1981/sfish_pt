# This script was automatically generated from the dsa-1599
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33367);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1599");
 script_cve_id("CVE-2008-0595");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1599 security update');
 script_set_attribute(attribute: 'description', value:
'Havoc Pennington discovered that DBus, a simple interprocess messaging
system, performs insufficient validation of security policies, which
might allow local privilege escalation.
For the stable distribution (etch), this problem has been fixed in
version 1.0.2-1+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1599');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your dbus packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1599] DSA-1599-1 dbus");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1599-1 dbus");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'dbus', release: '4.0', reference: '1.0.2-1+etch1');
deb_check(prefix: 'dbus-1-doc', release: '4.0', reference: '1.0.2-1+etch1');
deb_check(prefix: 'dbus-1-utils', release: '4.0', reference: '1.0.2-1+etch1');
deb_check(prefix: 'libdbus-1-3', release: '4.0', reference: '1.0.2-1+etch1');
deb_check(prefix: 'libdbus-1-dev', release: '4.0', reference: '1.0.2-1+etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
