# This script was automatically generated from the dsa-993
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22859);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "993");
 script_cve_id("CVE-2006-0049");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-993 security update');
 script_set_attribute(attribute: 'description', value:
'Tavis Ormandy noticed that gnupg, the GNU privacy guard - a free PGP
replacement, can be tricked to emit a "good signature" status message
when a valid signature is included which does not belong to the data
packet.  This update basically adds fixed packages for woody whose
version turned out to be vulnerable as well.
For the old stable distribution (woody) this problem has been fixed in
version 1.0.6-4woody5.
For the stable distribution (sarge) this problem has been fixed in
version 1.4.1-1.sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-993');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gnupg package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA993] DSA-993-2 gnupg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-993-2 gnupg");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnupg', release: '3.0', reference: '1.0.6-4woody5');
deb_check(prefix: 'gnupg', release: '3.1', reference: '1.4.1-1.sarge3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
