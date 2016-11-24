# This script was automatically generated from the dsa-1301
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25503);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1301");
 script_cve_id("CVE-2007-2356");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1301 security update');
 script_set_attribute(attribute: 'description', value:
'A buffer overflow has been identified in Gimp\'s SUNRAS plugin in
versions prior to 2.2.15.  This bug could allow an attacker to execute
arbitrary code on the victim\'s computer by inducing the victim to open a
specially crafted RAS file.
For the stable distribution (etch), this problem has been fixed in
version 2.2.13-1etch1.
For the old stable distribution (sarge), this problem has been fixed in
version 2.2.6-1sarge2.
For the unstable and testing distributions (sid and lenny,
respectively), this problem has been fixed in version 2.2.14-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1301');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gimp package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1301] DSA-1301-1 gimp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1301-1 gimp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gimp', release: '3.1', reference: '2.2.6-1sarge2');
deb_check(prefix: 'gimp-data', release: '3.1', reference: '2.2.6-1sarge2');
deb_check(prefix: 'gimp-helpbrowser', release: '3.1', reference: '2.2.6-1sarge2');
deb_check(prefix: 'gimp-python', release: '3.1', reference: '2.2.6-1sarge2');
deb_check(prefix: 'gimp-svg', release: '3.1', reference: '2.2.6-1sarge2');
deb_check(prefix: 'gimp1.2', release: '3.1', reference: '2.2.6-1sarge2');
deb_check(prefix: 'libgimp2.0', release: '3.1', reference: '2.2.6-1sarge2');
deb_check(prefix: 'libgimp2.0-dev', release: '3.1', reference: '2.2.6-1sarge2');
deb_check(prefix: 'libgimp2.0-doc', release: '3.1', reference: '2.2.6-1sarge2');
deb_check(prefix: 'gimp', release: '4.0', reference: '2.2.13-1etch1');
deb_check(prefix: 'gimp-data', release: '4.0', reference: '2.2.13-1etch1');
deb_check(prefix: 'gimp-dbg', release: '4.0', reference: '2.2.13-1etch1');
deb_check(prefix: 'gimp-helpbrowser', release: '4.0', reference: '2.2.13-1etch1');
deb_check(prefix: 'gimp-python', release: '4.0', reference: '2.2.13-1etch1');
deb_check(prefix: 'gimp-svg', release: '4.0', reference: '2.2.13-1etch1');
deb_check(prefix: 'libgimp2.0', release: '4.0', reference: '2.2.13-1etch1');
deb_check(prefix: 'libgimp2.0-dev', release: '4.0', reference: '2.2.13-1etch1');
deb_check(prefix: 'libgimp2.0-doc', release: '4.0', reference: '2.2.13-1etch1');
deb_check(prefix: 'gimp', release: '5.0', reference: '2.2.14-2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
