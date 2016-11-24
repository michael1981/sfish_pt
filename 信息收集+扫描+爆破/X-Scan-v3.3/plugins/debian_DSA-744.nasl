# This script was automatically generated from the dsa-744
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18652);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "744");
 script_cve_id("CVE-2005-1858");
 script_bugtraq_id(13857);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-744 security update');
 script_set_attribute(attribute: 'description', value:
'Sven Tantau discovered a security problem in fuse, a filesystem in
userspace, that can be exploited by malicious, local users to disclose
potentially sensitive information.
The old stable distribution (woody) does not contain the fuse package.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.1-4sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-744');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your fuse package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA744] DSA-744-1 fuse");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-744-1 fuse");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fuse-source', release: '3.1', reference: '2.2.1-4sarge2');
deb_check(prefix: 'fuse-utils', release: '3.1', reference: '2.2.1-4sarge2');
deb_check(prefix: 'libfuse-dev', release: '3.1', reference: '2.2.1-4sarge2');
deb_check(prefix: 'libfuse2', release: '3.1', reference: '2.2.1-4sarge2');
deb_check(prefix: 'fuse', release: '3.1', reference: '2.2.1-4sarge2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
