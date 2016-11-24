# This script was automatically generated from the dsa-1706
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35383);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1706");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1706 security update');
 script_set_attribute(attribute: 'description', value:
'Tobias Klein discovered that integer overflows in the code the Amarok
media player uses to parse Audible files may lead to the execution of
arbitrary code.
For the stable distribution (etch), this problem has been fixed in
version 1.4.4-4etch1. Updated packages for sparc and arm will be
provided later.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1706');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your amarok packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1706] DSA-1706-1 amarok");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1706-1 amarok");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'amarok', release: '4.0', reference: '1.4.4-4etch1');
deb_check(prefix: 'amarok-engines', release: '4.0', reference: '1.4.4-4etch1');
deb_check(prefix: 'amarok-xine', release: '4.0', reference: '1.4.4-4etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
