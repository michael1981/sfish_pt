# This script was automatically generated from the dsa-457
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15294);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "457");
 script_cve_id("CVE-2004-0148", "CVE-2004-0185");
 script_bugtraq_id(9832);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-457 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities were discovered in wu-ftpd:
 Glenn Stewart discovered that users could bypass the
 directory access restrictions imposed by the restricted-gid option by
 changing the permissions on their home directory.  On a subsequent
 login, when access to the user\'s home directory was denied, wu-ftpd
 would fall back to the root directory.
 A buffer overflow existed in wu-ftpd\'s code which
 deals with S/key authentication.
For the stable distribution (woody) these problems have been fixed in
version 2.6.2-3woody4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-457');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-457
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA457] DSA-457-1 wu-ftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-457-1 wu-ftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wu-ftpd', release: '3.0', reference: '2.6.2-3woody4');
deb_check(prefix: 'wu-ftpd-academ', release: '3.0', reference: '2.6.2-3woody4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
