# This script was automatically generated from the dsa-1422
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29257);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1422");
 script_cve_id("CVE-2007-5497");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1422 security update');
 script_set_attribute(attribute: 'description', value:
'Rafal Wojtczuk of McAfee AVERT Research discovered that e2fsprogs, the
ext2 file system utilities and libraries, contained multiple
integer overflows in memory allocations, based on sizes taken directly 
from filesystem information.  These could result in heap-based
overflows potentially allowing the execution of arbitrary code.
For the stable distribution (etch), this problem has been fixed in version
1.39+1.40-WIP-2006.11.14+dfsg-2etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1422');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your e2fsprogs package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1422] DSA-1422-1 e2fsprogs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1422-1 e2fsprogs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'comerr-dev', release: '4.0', reference: '2.1-1.39+1.40-WIP-2006.11.14+dfsg-2etch1');
deb_check(prefix: 'e2fsck-static', release: '4.0', reference: '1.39+1.40-WIP-2006.11.14+dfsg-2etch1');
deb_check(prefix: 'e2fslibs', release: '4.0', reference: '1.39+1.40-WIP-2006.11.14+dfsg-2etch1');
deb_check(prefix: 'e2fslibs-dev', release: '4.0', reference: '1.39+1.40-WIP-2006.11.14+dfsg-2etch1');
deb_check(prefix: 'e2fsprogs', release: '4.0', reference: '1.39+1.40-WIP-2006.11.14+dfsg-2etch1');
deb_check(prefix: 'libblkid-dev', release: '4.0', reference: '1.39+1.40-WIP-2006.11.14+dfsg-2etch1');
deb_check(prefix: 'libblkid1', release: '4.0', reference: '1.39+1.40-WIP-2006.11.14+dfsg-2etch1');
deb_check(prefix: 'libcomerr2', release: '4.0', reference: '1.39+1.40-WIP-2006.11.14+dfsg-2etch1');
deb_check(prefix: 'libss2', release: '4.0', reference: '1.39+1.40-WIP-2006.11.14+dfsg-2etch1');
deb_check(prefix: 'libuuid1', release: '4.0', reference: '1.39+1.40-WIP-2006.11.14+dfsg-2etch1');
deb_check(prefix: 'ss-dev', release: '4.0', reference: '2.0-1.39+1.40-WIP-2006.11.14+dfsg-2etch1');
deb_check(prefix: 'uuid-dev', release: '4.0', reference: '1.2-1.39+1.40-WIP-2006.11.14+dfsg-2etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
