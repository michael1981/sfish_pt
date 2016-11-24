# This script was automatically generated from the dsa-074
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14911);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "074");
 script_cve_id("CVE-2001-1027");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-074 security update');
 script_set_attribute(attribute: 'description', value:
'Alban Hertroys found a buffer overflow in Window Maker (a popular window
manager for X). The code that handles titles in the window list menu did
not check the length of the title when copying it to a buffer. Since
applications will set the title using data that can\'t be trusted (for
example, most web browsers will include the title of the web page being
shown in the title of their window), this could be exploited remotely.

This has been fixed in version 0.61.1-4.1 of the Debian package, and
upstream version 0.65.1.  We recommend that you update your Window
Maker package immediately. 

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-074');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-074
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA074] DSA-074-1 wmaker");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-074-1 wmaker");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libdockapp-dev', release: '2.2', reference: '0.61.1-4.1');
deb_check(prefix: 'libwings-dev', release: '2.2', reference: '0.61.1-4.1');
deb_check(prefix: 'libwmaker0-dev', release: '2.2', reference: '0.61.1-4.1');
deb_check(prefix: 'libwraster1', release: '2.2', reference: '0.61.1-4.1');
deb_check(prefix: 'libwraster1-dev', release: '2.2', reference: '0.61.1-4.1');
deb_check(prefix: 'wmaker', release: '2.2', reference: '0.61.1-4.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
