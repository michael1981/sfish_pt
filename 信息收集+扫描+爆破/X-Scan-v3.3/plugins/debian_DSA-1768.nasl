# This script was automatically generated from the dsa-1768
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36135);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1768");
 script_cve_id("CVE-2009-1250", "CVE-2009-1251");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1768 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities were discovered in the client part of OpenAFS, a
distributed file system.
CVE-2009-1251
An attacker with control of a file server or the ability to forge RX
packets may be able to execute arbitrary code in kernel mode on an
OpenAFS client, due to a vulnerability in XDR array decoding.
CVE-2009-1250
An attacker with control of a file server or the ability to forge RX
packets may crash OpenAFS clients because of wrongly handled error
return codes in the kernel module.
Note that in order to apply this security update, you must rebuild the
OpenAFS kernel module.  Be sure to also upgrade openafs-modules-source,
build a new kernel module for your system following the instructions in
/usr/share/doc/openafs-client/README.modules.gz, and then either stop
and restart openafs-client or reboot the system to reload the kernel
module.
For the old stable distribution (etch), these problems have been fixed
in version 1.4.2-6etch2.
For the stable distribution (lenny), these problems have been fixed in
version 1.4.7.dfsg1-6+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1768');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openafs packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1768] DSA-1768-1 openafs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1768-1 openafs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libopenafs-dev', release: '4.0', reference: '1.4.2-6etch2');
deb_check(prefix: 'libpam-openafs-kaserver', release: '4.0', reference: '1.4.2-6etch2');
deb_check(prefix: 'openafs-client', release: '4.0', reference: '1.4.2-6etch2');
deb_check(prefix: 'openafs-dbg', release: '4.0', reference: '1.4.2-6etch2');
deb_check(prefix: 'openafs-dbserver', release: '4.0', reference: '1.4.2-6etch2');
deb_check(prefix: 'openafs-doc', release: '4.0', reference: '1.4.2-6etch2');
deb_check(prefix: 'openafs-fileserver', release: '4.0', reference: '1.4.2-6etch2');
deb_check(prefix: 'openafs-kpasswd', release: '4.0', reference: '1.4.2-6etch2');
deb_check(prefix: 'openafs-krb5', release: '4.0', reference: '1.4.2-6etch2');
deb_check(prefix: 'openafs-modules-source', release: '4.0', reference: '1.4.2-6etch2');
deb_check(prefix: 'libopenafs-dev', release: '5.0', reference: '1.4.7.dfsg1-6+lenny1');
deb_check(prefix: 'libpam-openafs-kaserver', release: '5.0', reference: '1.4.7.dfsg1-6+lenny1');
deb_check(prefix: 'openafs-client', release: '5.0', reference: '1.4.7.dfsg1-6+lenny1');
deb_check(prefix: 'openafs-dbg', release: '5.0', reference: '1.4.7.dfsg1-6+lenny1');
deb_check(prefix: 'openafs-dbserver', release: '5.0', reference: '1.4.7.dfsg1-6+lenny1');
deb_check(prefix: 'openafs-doc', release: '5.0', reference: '1.4.7.dfsg1-6+lenny1');
deb_check(prefix: 'openafs-fileserver', release: '5.0', reference: '1.4.7.dfsg1-6+lenny1');
deb_check(prefix: 'openafs-kpasswd', release: '5.0', reference: '1.4.7.dfsg1-6+lenny1');
deb_check(prefix: 'openafs-krb5', release: '5.0', reference: '1.4.7.dfsg1-6+lenny1');
deb_check(prefix: 'openafs-modules-source', release: '5.0', reference: '1.4.7.dfsg1-6+lenny1');
deb_check(prefix: 'openafs', release: '4.0', reference: '1.4.2-6etch2');
deb_check(prefix: 'openafs', release: '5.0', reference: '1.4.7.dfsg1-6+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
