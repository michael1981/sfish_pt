# This script was automatically generated from the dsa-1060
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22602);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1060");
 script_cve_id("CVE-2006-2110");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1060 security update');
 script_set_attribute(attribute: 'description', value:
'Jan Rekorajski discovered that the kernel patch for virtual private servers
does not limit context capabilities to the root user within the virtual
server, which might lead to privilege escalation for some virtual server
specific operations.
The old stable distribution (woody) does not contain kernel-patch-vserver
packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.9.5.6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1060');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kernel-patch-vserver package and
rebuild your kernel immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1060] DSA-1060-1 kernel-patch-vserver");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1060-1 kernel-patch-vserver");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kernel-patch-vserver', release: '3.1', reference: '1.9.5.6');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
