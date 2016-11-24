# This script was automatically generated from the dsa-085
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14922);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "085");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-085 security update');
 script_set_attribute(attribute: 'description', value:
'Takeshi Uno found a very stupid format string vulnerability in all
versions of nvi (in both, the plain and the multilingualized version).
When a filename is saved, it ought to get displayed on the screen.
The routine handling this didn\'t escape format strings.

This problem has been fixed in version 1.79-16a.1 for nvi and
1.79+19991117-2.3 for nvi-m17n for the stable Debian GNU/Linux 2.2.

Even if we don\'t believe that this could lead into somebody gaining
access of another users account if they haven\'t lost their brain, we
recommend that you upgrade your nvi packages.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-085');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-085
and install the recommended updated packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA085] DSA-085-1 nvi");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-085-1 nvi");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'nvi', release: '2.2', reference: '1.79-16a.1');
deb_check(prefix: 'nvi-m17n', release: '2.2', reference: '1.79+19991117-2.3');
deb_check(prefix: 'nvi-m17n-canna', release: '2.2', reference: '1.79+19991117-2.3');
deb_check(prefix: 'nvi-m17n-common', release: '2.2', reference: '1.79+19991117-2.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
