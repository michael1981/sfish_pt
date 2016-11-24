# This script was automatically generated from the dsa-1458
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29935);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1458");
 script_cve_id("CVE-2007-6599");
 script_bugtraq_id(27132);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1458 security update');
 script_set_attribute(attribute: 'description', value:
'A race condition in the OpenAFS fileserver allows remote attackers to
cause a denial of service (daemon crash) by simultaneously acquiring and
giving back file callbacks, which causes the handler for the
GiveUpAllCallBacks RPC to perform linked-list operations without the
host_glock lock.


For the old stable distribution (sarge), this problem has been fixed in
version 1.3.81-3sarge3.


For the stable distribution (etch), this problem has been fixed in
version 1.4.2-6etch1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1458');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openafs packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1458] DSA-1458-1 openafs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1458-1 openafs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libopenafs-dev', release: '3.1', reference: '1.3.81-3sarge3');
deb_check(prefix: 'libpam-openafs-kaserver', release: '3.1', reference: '1.3.81-3sarge3');
deb_check(prefix: 'openafs-client', release: '3.1', reference: '1.3.81-3sarge3');
deb_check(prefix: 'openafs-dbserver', release: '3.1', reference: '1.3.81-3sarge3');
deb_check(prefix: 'openafs-fileserver', release: '3.1', reference: '1.3.81-3sarge3');
deb_check(prefix: 'openafs-kpasswd', release: '3.1', reference: '1.3.81-3sarge3');
deb_check(prefix: 'openafs-modules-source', release: '3.1', reference: '1.3.81-3sarge3');
deb_check(prefix: 'libopenafs-dev', release: '4.0', reference: '1.4.2-6etch1');
deb_check(prefix: 'libpam-openafs-kaserver', release: '4.0', reference: '1.4.2-6etch1');
deb_check(prefix: 'openafs-client', release: '4.0', reference: '1.4.2-6etch1');
deb_check(prefix: 'openafs-dbg', release: '4.0', reference: '1.4.2-6etch1');
deb_check(prefix: 'openafs-dbserver', release: '4.0', reference: '1.4.2-6etch1');
deb_check(prefix: 'openafs-doc', release: '4.0', reference: '1.4.2-6etch1');
deb_check(prefix: 'openafs-fileserver', release: '4.0', reference: '1.4.2-6etch1');
deb_check(prefix: 'openafs-kpasswd', release: '4.0', reference: '1.4.2-6etch1');
deb_check(prefix: 'openafs-krb5', release: '4.0', reference: '1.4.2-6etch1');
deb_check(prefix: 'openafs-modules-source', release: '4.0', reference: '1.4.2-6etch1');
deb_check(prefix: 'openafs', release: '4.0', reference: '1.4.2-6etch1');
deb_check(prefix: 'openafs', release: '3.1', reference: '1.3.81-3sarge3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
