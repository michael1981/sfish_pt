# This script was automatically generated from the dsa-1580
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32402);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1580");
 script_cve_id("CVE-2008-2064");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1580 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that phpGedView, an application to provide online access
to genealogical data, allowed remote attackers to gain administrator
privileges due to a programming error.
Note: this problem was a fundamental design flaw in the interface (API) to
connect phpGedView with external programs like content management systems.
Resolving this problem was only possible by completely reworking the API,
which is not considered appropriate for a security update. Since these are
peripheral functions probably not used by the large majority of package
users, it was decided to remove these interfaces. If you require that
interface nonetheless, you are advised to use a version of phpGedView
backported from Debian Lenny, which has a completely redesigned API.
For the stable distribution (etch), this problem has been fixed in version
4.0.2.dfsg-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1580');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpgedview package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1580] DSA-1580-1 phpgedview");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1580-1 phpgedview");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpgedview', release: '4.0', reference: '4.0.2.dfsg-4');
deb_check(prefix: 'phpgedview-languages', release: '4.0', reference: '4.0.2.dfsg-4');
deb_check(prefix: 'phpgedview-places', release: '4.0', reference: '4.0.2.dfsg-4');
deb_check(prefix: 'phpgedview-themes', release: '4.0', reference: '4.0.2.dfsg-4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
