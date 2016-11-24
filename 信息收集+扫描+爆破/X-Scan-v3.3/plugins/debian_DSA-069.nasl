# This script was automatically generated from the dsa-069
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14906);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "069");
 script_cve_id("CVE-2001-0775");
 script_bugtraq_id(3006);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-069 security update');
 script_set_attribute(attribute: 'description', value:
'The version of xloadimage (a graphics files viewer for X) that was
shipped in Debian GNU/Linux 2.2 has a buffer overflow in the code that
handles FACES format images. This could be exploited by an attacker by
tricking someone into viewing a specially crafted image using xloadimage
which would allow them to execute arbitrary code.

This problem was fixed in version 4.1-5potato1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-069');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-069
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA069] DSA-069-1 xloadimage");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-069-1 xloadimage");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xloadimage', release: '2.2', reference: '4.1-5potato1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
