# This script was automatically generated from the dsa-140
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14977);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "140");
 script_cve_id("CVE-2002-0660", "CVE-2002-0728");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-140 security update');
 script_set_attribute(attribute: 'description', value:
'Developers of the PNG library have fixed a buffer overflow in the
progressive reader when the PNG datastream contains more IDAT data
than indicated by the IHDR chunk.  Such deliberately malformed
datastreams would crash applications which could potentially allow an
attacker to execute malicious code.  Programs such as Galeon,
Konqueror and various others make use of these libraries.
In addition to that, the packages below fix another
potential buffer overflow.  The PNG libraries implement a safety
margin which is also included in a newer upstream release.  Thanks to
Glenn Randers-Pehrson for informing us.
To find out which packages depend on this library, you may want to
execute the following commands:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-140');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libpng packages immediately and
restart programs and daemons that link to these libraries and read
external data, such as web browsers.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA140] DSA-140-2 libpng");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-140-2 libpng");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpng-dev', release: '3.0', reference: '1.2.1-1.1.woody.2');
deb_check(prefix: 'libpng2', release: '3.0', reference: '1.0.12-3.woody.2');
deb_check(prefix: 'libpng2-dev', release: '3.0', reference: '1.0.12-3.woody.2');
deb_check(prefix: 'libpng3', release: '3.0', reference: '1.2.1-1.1.woody.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
