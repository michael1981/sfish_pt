# This script was automatically generated from the dsa-1170
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22712);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1170");
 script_cve_id("CVE-2006-3619");
 script_bugtraq_id(15669);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1170 security update');
 script_set_attribute(attribute: 'description', value:
'Jürgen Weigert discovered that upon unpacking JAR archives fastjar
from the GNU Compiler Collection does not check the path for included
files and allows to create or overwrite files in upper directories.
For the stable distribution (sarge) this problem has been fixed in
version 3.4.3-13sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1170');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your fastjar package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1170] DSA-1170-1 gcc-3.4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1170-1 gcc-3.4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cpp-3.4', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'cpp-3.4-doc', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'fastjar', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'g77-3.4', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'g77-3.4-doc', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'gcc-3.4', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'gcc-3.4-base', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'gcc-3.4-doc', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'gcc-3.4-hppa64', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'gcj-3.4', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'gij-3.4', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'gnat-3.4', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'gnat-3.4-doc', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'gobjc-3.4', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'gpc-2.1-3.4', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'gpc-2.1-3.4-doc', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'lib32gcc1', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'lib64gcc1', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'libffi3', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'libffi3-dev', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'libgcc1', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'libgcc2', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'libgcj5', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'libgcj5-awt', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'libgcj5-common', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'libgcj5-dev', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'libgnat-3.4', release: '3.1', reference: '3.4.3-13sarge1');
deb_check(prefix: 'treelang-3.4', release: '3.1', reference: '3.4.3-13sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
