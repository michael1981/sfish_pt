# This script was automatically generated from the dsa-571
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15669);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "571");
 script_cve_id("CVE-2004-0599");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-571 security update');
 script_set_attribute(attribute: 'description', value:
'Several integer overflows have been discovered by its upstream
developers in libpng, a commonly used library to display PNG graphics.
They could be exploited to cause arbitrary code to be executed when a
specially crafted PNG image is processed.
For the stable distribution (woody) these problems have been fixed in
version 1.2.1-1.1.woody.9.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-571');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libpng3 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA571] DSA-571-1 libpng3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-571-1 libpng3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpng-dev', release: '3.0', reference: '1.2.1-1.1.woody.9');
deb_check(prefix: 'libpng3', release: '3.0', reference: '1.2.1-1.1.woody.9');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
