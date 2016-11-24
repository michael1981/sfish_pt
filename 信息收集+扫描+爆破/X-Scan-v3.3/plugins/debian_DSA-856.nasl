# This script was automatically generated from the dsa-856
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19964);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "856");
 script_cve_id("CVE-2005-2875");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-856 security update');
 script_set_attribute(attribute: 'description', value:
'Arc Riley discovered that py2play, a peer-to-peer network game engine,
is able to execute arbitrary code received from the p2p game network
it is connected to without any security checks.
The old stable distribution (woody) does not contain py2play packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.1.7-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-856');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your py2play package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA856] DSA-856-1 py2play");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-856-1 py2play");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'python-2play', release: '3.1', reference: '0.1.7-1sarge1');
deb_check(prefix: 'py2play', release: '3.1', reference: '0.1.7-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
