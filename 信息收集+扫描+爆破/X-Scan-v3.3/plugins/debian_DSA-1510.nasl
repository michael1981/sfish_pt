# This script was automatically generated from the dsa-1510
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31303);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1510");
 script_cve_id("CVE-2008-0411");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1510 security update');
 script_set_attribute(attribute: 'description', value:
'Chris Evans discovered a buffer overflow in the color space handling
code of the Ghostscript PostScript/PDF interpreter, which might result
in the execution of arbitrary code if a user is tricked into processing
a malformed file.
For the stable distribution (etch), this problem has been fixed in version
8.54.dfsg.1-5etch1 of gs-gpl and 8.15.3.dfsg.1-1etch1 of gs-esp.
For the old stable distribution (sarge), this problem has been fixed in
version 8.01-6 of gs-gpl and 7.07.1-9sarge1 of gs-esp.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1510');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gs-esp and gs-gpl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1510] DSA-1510-1 ghostscript");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1510-1 ghostscript");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gs', release: '3.1', reference: '8.01-6');
deb_check(prefix: 'gs-esp', release: '3.1', reference: '7.07.1-9sarge1');
deb_check(prefix: 'gs-gpl', release: '3.1', reference: '8.01-6');
deb_check(prefix: 'gs', release: '4.0', reference: '8.54.dfsg.1-5etch1');
deb_check(prefix: 'gs-esp', release: '4.0', reference: '8.15.3.dfsg.1-1etch1');
deb_check(prefix: 'gs-gpl', release: '4.0', reference: '8.54.dfsg.1-5etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
