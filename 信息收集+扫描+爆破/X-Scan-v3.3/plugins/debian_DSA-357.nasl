# This script was automatically generated from the dsa-357
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15194);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "357");
 script_cve_id("CVE-2003-0466");
 script_bugtraq_id(8315);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-357 security update');
 script_set_attribute(attribute: 'description', value:
'iSEC Security Research reports that wu-ftpd contains an off-by-one bug
in the fb_realpath function which could be exploited by a logged-in user
(local or anonymous) to gain root privileges. A demonstration exploit is
reportedly available.
For the current stable distribution (woody) this problem has been fixed
in version 2.6.2-3woody1. 
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-357');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-357
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA357] DSA-357-1 wu-ftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-357-1 wu-ftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wu-ftpd', release: '3.0', reference: '2.6.2-3woody1');
deb_check(prefix: 'wu-ftpd-academ', release: '3.0', reference: '2.6.2-3woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
