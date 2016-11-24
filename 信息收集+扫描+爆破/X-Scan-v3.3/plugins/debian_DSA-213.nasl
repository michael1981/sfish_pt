# This script was automatically generated from the dsa-213
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15050);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "213");
 script_cve_id("CVE-2002-1363");
 script_bugtraq_id(6431);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-213 security update');
 script_set_attribute(attribute: 'description', value:
'Glenn Randers-Pehrson discovered a problem in connection with 16-bit
samples from libpng, an interface for reading and writing PNG
(Portable Network Graphics) format files.  The starting offsets for
the loops are calculated incorrectly which causes a buffer overrun
beyond the beginning of the row buffer.
For the current stable distribution (woody) this problem has been
fixed in version 1.0.12-3.woody.3 for libpng and in version
1.2.1-1.1.woody.3 for libpng3.
For the old stable distribution (potato) this problem has been fixed
in version 1.0.5-1.1 for libpng.  There are no other libpng packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-213');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libpng packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA213] DSA-213-1 libpng");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-213-1 libpng");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpng2', release: '2.2', reference: '1.0.5-1.1');
deb_check(prefix: 'libpng2-dev', release: '2.2', reference: '1.0.5-1.1');
deb_check(prefix: 'libpng-dev', release: '3.0', reference: '1.2.1-1.1.woody.3');
deb_check(prefix: 'libpng2', release: '3.0', reference: '1.0.12-3.woody.3');
deb_check(prefix: 'libpng2-dev', release: '3.0', reference: '1.0.12-3.woody.3');
deb_check(prefix: 'libpng3', release: '3.0', reference: '1.2.1-1.1.woody.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
