# This script was automatically generated from the dsa-127
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14964);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "127");
 script_cve_id("CVE-2002-0179");
 script_bugtraq_id(4534);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-127 security update');
 script_set_attribute(attribute: 'description', value:
'An internal audit by the xpilot (a multi-player tactical manoeuvring
game for X) maintainers revealed a buffer overflow in xpilot server.
This overflow can be abused by remote attackers to gain access to
the server under which the xpilot server is running.
This has been fixed in upstream version 4.5.1 and version
4.1.0-4.U.4alpha2.4.potato1 of the Debian package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-127');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-127
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA127] DSA-127-1 xpilot-server");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-127-1 xpilot-server");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xpilot', release: '2.2', reference: '4.1.0-4.U.4alpha2.4.potato1');
deb_check(prefix: 'xpilot-client-nas', release: '2.2', reference: '4.1.0-4.U.4alpha2.4.potato1');
deb_check(prefix: 'xpilot-client-nosound', release: '2.2', reference: '4.1.0-4.U.4alpha2.4.potato1');
deb_check(prefix: 'xpilot-client-rplay', release: '2.2', reference: '4.1.0-4.U.4alpha2.4.potato1');
deb_check(prefix: 'xpilot-server', release: '2.2', reference: '4.1.0-4.U.4alpha2.4.potato1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
