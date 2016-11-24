# This script was automatically generated from the dsa-1271
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24880);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1271");
 script_cve_id("CVE-2007-1507");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1271 security update');
 script_set_attribute(attribute: 'description', value:
'A design error has been identified in the OpenAFS, a cross-platform
distributed filesystem included with Debian.
OpenAFS historically has enabled setuid filesystem support for the local
cell.  However, with its existing protocol, OpenAFS can only use
encryption, and therefore integrity protection, if the user is
authenticated.  Unauthenticated access doesn\'t do integrity protection.
The practical result is that it\'s possible for an attacker with
knowledge of AFS to forge an AFS FetchStatus call and make an arbitrary
binary file appear to an AFS client host to be setuid.  If they can then
arrange for that binary to be executed, they will be able to achieve
privilege escalation.
OpenAFS 1.3.81-3sarge2 changes the default behavior to disable setuid
files globally, including the local cell.  It is important to note that
this change will not take effect until the AFS kernel module, built from
the openafs-modules-source package, is rebuilt and loaded into your
kernel.  As a temporary workaround until the kernel module can be
reloaded, setuid support can be manually disabled for the local cell by
running the following command as root
Following the application of this update, if you are certain there is
no security risk of an attacker forging AFS fileserver responses, you
can re-enable setuid status selectively with the following command,
however this should not be done on sites that are visible to the
Internet
For the stable distribution (sarge), this problem has been fixed in
version 1.3.81-3sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1271');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openafs package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1271] DSA-1271-1 openafs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1271-1 openafs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libopenafs-dev', release: '3.1', reference: '1.3.81-3sarge2');
deb_check(prefix: 'libpam-openafs-kaserver', release: '3.1', reference: '1.3.81-3sarge2');
deb_check(prefix: 'openafs-client', release: '3.1', reference: '1.3.81-3sarge2');
deb_check(prefix: 'openafs-dbserver', release: '3.1', reference: '1.3.81-3sarge2');
deb_check(prefix: 'openafs-fileserver', release: '3.1', reference: '1.3.81-3sarge2');
deb_check(prefix: 'openafs-kpasswd', release: '3.1', reference: '1.3.81-3sarge2');
deb_check(prefix: 'openafs-modules-source', release: '3.1', reference: '1.3.81-3sarge2');
deb_check(prefix: 'openafs', release: '3.1', reference: '1.3.81-3sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
