# This script was automatically generated from the dsa-037
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14874);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "037");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-037 security update');
 script_set_attribute(attribute: 'description', value:
'It has been reported that the AsciiSrc and MultiSrc widget
in the Athena widget library handle temporary files insecurely.  Joey Hess has
ported the bugfix from XFree86 to these Xaw replacements libraries. The fixes
are available in nextaw 0.5.1-34potato1, xaw3d 1.3-6.9potato1, and xaw95
1.1-4.6potato1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-037');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-037
and install the recommended updated packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA037] DSA-037-1 Athena Widget replacement libraries");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-037-1 Athena Widget replacement libraries");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'nextaw', release: '2.2', reference: '0.5.1-34potato1');
deb_check(prefix: 'nextawg', release: '2.2', reference: '0.5.1-34potato1');
deb_check(prefix: 'xaw3d', release: '2.2', reference: '1.3-6.9potato1');
deb_check(prefix: 'xaw3dg', release: '2.2', reference: '1.3-6.9potato1');
deb_check(prefix: 'xaw3dg-dev', release: '2.2', reference: '1.3-6.9potato1');
deb_check(prefix: 'xaw95g', release: '2.2', reference: '1.1-4.6potato1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
