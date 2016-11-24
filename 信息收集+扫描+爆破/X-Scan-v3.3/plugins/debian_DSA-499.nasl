# This script was automatically generated from the dsa-499
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15336);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "499");
 script_cve_id("CVE-2004-0426");
 script_bugtraq_id(10247);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-499 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability was discovered in rsync, a file transfer program,
whereby a remote user could cause an rsync daemon to write files
outside of the intended directory tree.  This vulnerability is not
exploitable when the daemon is configured with the \'chroot\' option.
For the current stable distribution (woody) this problem has been
fixed in version 2.5.5-0.5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-499');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-499
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA499] DSA-499-2 rsync");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-499-2 rsync");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'rsync', release: '3.0', reference: '2.5.5-0.5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
