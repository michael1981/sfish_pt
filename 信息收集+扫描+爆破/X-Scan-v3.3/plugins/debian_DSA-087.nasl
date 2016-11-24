# This script was automatically generated from the dsa-087
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14924);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "087");
 script_cve_id("CVE-2001-0550");
 script_bugtraq_id(3581);
 script_xref(name: "CERT", value: "886083");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-087 security update');
 script_set_attribute(attribute: 'description', value:
'CORE ST reports that an exploit has been found for a bug in the wu-ftpd
glob code (this is the code that handles filename wildcard expansion).
Any logged in user (including anonymous FTP users) can exploit the bug
to gain root privileges on the server. 

This has been corrected in version 2.6.0-6 of the wu-ftpd package.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-087');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-087
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA087] DSA-087-1 wu-ftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-087-1 wu-ftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wu-ftpd', release: '2.2', reference: '2.6.0-6');
deb_check(prefix: 'wu-ftpd-academ', release: '2.2', reference: '2.6.0-6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
