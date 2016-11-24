# This script was automatically generated from the dsa-1343
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25826);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1343");
 script_cve_id("CVE-2007-2799");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1343 security update');
 script_set_attribute(attribute: 'description', value:
'Colin Percival discovered an integer overflow in file, a file type
classification tool, which may lead to the execution of arbitrary code.
For the oldstable distribution (sarge) this problem has been fixed in
version 4.12-1sarge2.
For the stable distribution (etch) this problem has been fixed in
version 4.17-5etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1343');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your file package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1343] DSA-1343-1 file");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1343-1 file");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'file', release: '3.1', reference: '4.12-1sarge2');
deb_check(prefix: 'libmagic-dev', release: '3.1', reference: '4.12-1sarge2');
deb_check(prefix: 'libmagic1', release: '3.1', reference: '4.12-1sarge2');
deb_check(prefix: 'file', release: '4.0', reference: '4.17-5etch2');
deb_check(prefix: 'libmagic-dev', release: '4.0', reference: '4.17-5etch2');
deb_check(prefix: 'libmagic1', release: '4.0', reference: '4.17-5etch2');
deb_check(prefix: 'python-magic', release: '4.0', reference: '4.17-5etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
