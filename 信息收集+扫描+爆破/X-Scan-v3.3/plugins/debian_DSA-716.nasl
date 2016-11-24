# This script was automatically generated from the dsa-716
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18152);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "716");
 script_cve_id("CVE-2005-0472");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-716 security update');
 script_set_attribute(attribute: 'description', value:
'It has been discovered that certain malformed SNAC packets sent by
other AIM or ICQ users can trigger an infinite loop in Gaim, a
multi-protocol instant messaging client, and hence lead to a denial of
service of the client.
Two more denial of service conditions have been discovered in newer
versions of Gaim which are fixed in the package in sid but are not
present in the package in woody.
For the stable distribution (woody) this problem has been fixed in
version 0.58-2.5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-716');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gaim packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA716] DSA-716-1 gaim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-716-1 gaim");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gaim', release: '3.0', reference: '0.58-2.5');
deb_check(prefix: 'gaim-common', release: '3.0', reference: '0.58-2.5');
deb_check(prefix: 'gaim-gnome', release: '3.0', reference: '0.58-2.5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
