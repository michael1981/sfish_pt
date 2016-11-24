# This script was automatically generated from the dsa-1822
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(39495);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1822");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1822 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that mahara, an electronic portfolio, weblog, and resume
builder is prone to several cross-site scripting attacks, which allow an
attacker to inject arbitrary HTML or script code and steal potential sensitive
data from other users.
The oldstable distribution (etch) does not contain mahara.
For the stable distribution (lenny), this problem has been fixed in
version 1.0.4-4+lenny3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1822');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mahara packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1822] DSA-1822-1 mahara");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1822-1 mahara");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mahara', release: '5.0', reference: '1.0.4-4+lenny3');
deb_check(prefix: 'mahara-apache2', release: '5.0', reference: '1.0.4-4+lenny3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
