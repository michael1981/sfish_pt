# This script was automatically generated from the dsa-730
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18517);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "730");
 script_cve_id("CVE-2005-0953");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-730 security update');
 script_set_attribute(attribute: 'description', value:
'Imran Ghory discovered a race condition in bzip2, a high-quality
block-sorting file compressor and decompressor.  When decompressing a
file in a directory an attacker has access to, bunzip2 could be
tricked to set the file permissions to a different file the user has
permissions to.
For the stable distribution (woody) this problem has been fixed in
version 1.0.2-1.woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-730');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your bzip2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA730] DSA-730-1 bzip2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-730-1 bzip2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bzip2', release: '3.0', reference: '1.0.2-1.woody2');
deb_check(prefix: 'libbz2-1.0', release: '3.0', reference: '1.0.2-1.woody2');
deb_check(prefix: 'libbz2-dev', release: '3.0', reference: '1.0.2-1.woody2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
