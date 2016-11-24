# This script was automatically generated from the dsa-040
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14877);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "040");
 script_cve_id("CVE-2001-0441");
 script_bugtraq_id(2493);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-040 security update');
 script_set_attribute(attribute: 'description', value:
'Bill Nottingham reported a problem in the
wrapping/unwrapping functions of the slrn newsreader. A long header in a
message might overflow a buffer, which could result in executing arbitrary
code encoded in the message.

The default configuration does not have wrapping enable, but it can easily
be enabled either by changing the configuration or pressing W while viewing a
message.

This has been fixed in version 0.9.6.2-9potato1 and we recommand that you
upgrade your slrn package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-040');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-040
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA040] DSA-040-1 slrn");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-040-1 slrn");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'slrn', release: '2.2', reference: '0.9.6.2-9potato1');
deb_check(prefix: 'slrnpull', release: '2.2', reference: '0.9.6.2-9potato1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
