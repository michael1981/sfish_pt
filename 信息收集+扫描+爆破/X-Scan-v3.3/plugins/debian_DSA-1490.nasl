# This script was automatically generated from the dsa-1490
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30229);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1490");
 script_cve_id("CVE-2008-0553");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1490 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that a buffer overflow in the GIF image parsing code
of Tk, a cross-platform graphical toolkit, could lead to a denial of
service and potentially the execution of arbitrary code.
For the old stable distribution (sarge), this problem has been fixed in
version 8.3.5-4sarge1.
For the stable distribution (etch), this problem has been fixed in
version 8.3.5-6etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1490');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tk8.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1490] DSA-1490-1 tk8.3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1490-1 tk8.3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tk8.3', release: '3.1', reference: '8.3.5-4sarge1');
deb_check(prefix: 'tk8.3-dev', release: '3.1', reference: '8.3.5-4sarge1');
deb_check(prefix: 'tk8.3-doc', release: '3.1', reference: '8.3.5-4sarge1');
deb_check(prefix: 'tk8.3', release: '4.0', reference: '8.3.5-6etch2');
deb_check(prefix: 'tk8.3-dev', release: '4.0', reference: '8.3.5-6etch2');
deb_check(prefix: 'tk8.3-doc', release: '4.0', reference: '8.3.5-6etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
