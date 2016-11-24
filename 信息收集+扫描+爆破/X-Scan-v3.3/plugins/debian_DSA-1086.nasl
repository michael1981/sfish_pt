# This script was automatically generated from the dsa-1086
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22628);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1086");
 script_cve_id("CVE-2006-2542");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1086 security update');
 script_set_attribute(attribute: 'description', value:
'The xmcdconfig creates directories world-writeable allowing local
users to fill the /usr and /var partition and hence cause a denial of
service.  This problem has been half-fixed since version 2.3-1.
For the old stable distribution (woody) this problem has been fixed in
version 2.6-14woody1.
For the stable distribution (sarge) this problem has been fixed in
version 2.6-17sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1086');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xmcd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1086] DSA-1086-1 xmcd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1086-1 xmcd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cddb', release: '3.0', reference: '2.6-14woody1');
deb_check(prefix: 'xmcd', release: '3.0', reference: '2.6-14woody1');
deb_check(prefix: 'cddb', release: '3.1', reference: '2.6-17sarge1');
deb_check(prefix: 'xmcd', release: '3.1', reference: '2.6-17sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
