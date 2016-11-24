# This script was automatically generated from the dsa-1469
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30061);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1469");
 script_cve_id("CVE-2007-4619", "CVE-2007-6277");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1469 security update');
 script_set_attribute(attribute: 'description', value:
'Sean de Regge and Greg Linares discovered multiple heap and stack based
buffer overflows in FLAC, the Free Lossless Audio Codec, which could
lead to the execution of arbitrary code.
For the old stable distribution (sarge), these problems have been
fixed in version 1.1.1-5sarge1.
For the stable distribution (etch), these problems have been fixed in
version 1.1.2-8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1469');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your flac packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1469] DSA-1469-1 flac");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1469-1 flac");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'flac', release: '3.1', reference: '1.1.1-5sarge1');
deb_check(prefix: 'libflac-dev', release: '3.1', reference: '1.1.1-5sarge1');
deb_check(prefix: 'libflac6', release: '3.1', reference: '1.1.1-5sarge1');
deb_check(prefix: 'liboggflac-dev', release: '3.1', reference: '1.1.1-5sarge1');
deb_check(prefix: 'liboggflac1', release: '3.1', reference: '1.1.1-5sarge1');
deb_check(prefix: 'xmms-flac', release: '3.1', reference: '1.1.1-5sarge1');
deb_check(prefix: 'flac', release: '4.0', reference: '1.1.2-8');
deb_check(prefix: 'libflac-dev', release: '4.0', reference: '1.1.2-8');
deb_check(prefix: 'libflac-doc', release: '4.0', reference: '1.1.2-8');
deb_check(prefix: 'libflac7', release: '4.0', reference: '1.1.2-8');
deb_check(prefix: 'liboggflac-dev', release: '4.0', reference: '1.1.2-8');
deb_check(prefix: 'liboggflac3', release: '4.0', reference: '1.1.2-8');
deb_check(prefix: 'xmms-flac', release: '4.0', reference: '1.1.2-8');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
