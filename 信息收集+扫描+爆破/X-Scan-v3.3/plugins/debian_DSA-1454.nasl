# This script was automatically generated from the dsa-1454
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29873);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1454");
 script_cve_id("CVE-2007-1351");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1454 security update');
 script_set_attribute(attribute: 'description', value:
'Greg MacManus discovered an integer overflow in the font handling of
libfreetype, a FreeType 2 font engine, which might lead to denial of
service or possibly the execution of arbitrary code if a user is tricked
into opening a malformed font.


For the old stable distribution (sarge) this problem will be fixed
soon.


For the stable distribution (etch), this problem has been fixed in
version 2.2.1-5+etch2.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1454');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your freetype packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1454] DSA-1454-1 freetype");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1454-1 freetype");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'freetype2-demos', release: '4.0', reference: '2.2.1-5+etch2');
deb_check(prefix: 'libfreetype6', release: '4.0', reference: '2.2.1-5+etch2');
deb_check(prefix: 'libfreetype6-dev', release: '4.0', reference: '2.2.1-5+etch2');
deb_check(prefix: 'freetype', release: '4.0', reference: '2.2.1-5+etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
