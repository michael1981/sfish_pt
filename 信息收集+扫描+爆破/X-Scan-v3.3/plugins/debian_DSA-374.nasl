# This script was automatically generated from the dsa-374
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15211);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "374");
 script_cve_id("CVE-2003-0686");
 script_bugtraq_id(8491);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-374 security update');
 script_set_attribute(attribute: 'description', value:
'libpam-smb is a PAM authentication module which makes it possible to
authenticate users against a password database managed by Samba or a
Microsoft Windows server.  If a long password is supplied, this can
cause a buffer overflow which could be exploited to execute arbitrary
code with the privileges of the process which invokes PAM services.
For the stable distribution (woody) this problem has been fixed in
version 1.1.6-1.1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-374');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-374
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA374] DSA-374-1 libpam-smb");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-374-1 libpam-smb");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-smb', release: '3.0', reference: '1.1.6-1.1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
