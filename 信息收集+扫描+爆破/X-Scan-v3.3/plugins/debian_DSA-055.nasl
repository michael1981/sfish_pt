# This script was automatically generated from the dsa-055
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14892);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "055");
 script_cve_id("CVE-2001-0567");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-055 security update');
 script_set_attribute(attribute: 'description', value:
'A new Zope hotfix has been released which fixes a problem in ZClasses.
The README for the 2001-05-01 hotfix describes the problem as `any user
can visit a ZClass declaration and change the ZClass permission mappings
for methods and other objects defined within the ZClass, possibly
allowing for unauthorized access within the Zope instance.\'

This hotfix has been added in version 2.1.6-10, and we highly recommend
that you upgrade your zope package immediately.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-055');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-055
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA055] DSA-055-1 zope");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-055-1 zope");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'zope', release: '2.2', reference: '2.1.6-10');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
