# This script was automatically generated from the dsa-493
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15330);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "493");
 script_cve_id("CVE-2004-0409");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-493 security update');
 script_set_attribute(attribute: 'description', value:
'A buffer overflow has been discovered in the Socks-5 proxy code of
XChat, an IRC client for X similar to AmIRC.  This allows an attacker
to execute arbitrary code on the users\' machine.
For the stable distribution (woody) this problem has been fixed in
version 1.8.9-0woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-493');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xchat and related packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA493] DSA-493-1 xchat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-493-1 xchat");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xchat', release: '3.0', reference: '1.8.9-0woody3');
deb_check(prefix: 'xchat-common', release: '3.0', reference: '1.8.9-0woody3');
deb_check(prefix: 'xchat-gnome', release: '3.0', reference: '1.8.9-0woody3');
deb_check(prefix: 'xchat-text', release: '3.0', reference: '1.8.9-0woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
