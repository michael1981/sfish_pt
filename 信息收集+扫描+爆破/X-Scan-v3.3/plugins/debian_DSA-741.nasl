# This script was automatically generated from the dsa-741
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18645);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "741");
 script_cve_id("CVE-2005-1260");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-741 security update');
 script_set_attribute(attribute: 'description', value:
'Chris Evans discovered that a specially crafted archive can trigger an
infinite loop in bzip2, a high-quality block-sorting file compressor.
During uncompression this results in an indefinitely growing output
file which will finally fill up the disk.  On systems that
automatically decompress bzip2 archives this can cause a denial of
service.
For the oldstable distribution (woody) this problem has been fixed in
version 1.0.2-1.woody5.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.2-7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-741');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your bzip2 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA741] DSA-741-1 bzip2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-741-1 bzip2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bzip2', release: '3.0', reference: '1.0.2-1.woody5');
deb_check(prefix: 'libbz2-1.0', release: '3.0', reference: '1.0.2-1.woody5');
deb_check(prefix: 'libbz2-dev', release: '3.0', reference: '1.0.2-1.woody5');
deb_check(prefix: 'bzip2', release: '3.1', reference: '1.0.2-7');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
