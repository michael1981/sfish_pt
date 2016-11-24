# This script was automatically generated from the dsa-1140
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22682);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1140");
 script_cve_id("CVE-2006-3746");
 script_bugtraq_id(19110);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1140 security update');
 script_set_attribute(attribute: 'description', value:
'Evgeny Legerov discovered that overly large comments can crash gnupg,
the GNU privacy guard - a free PGP replacement.
For the stable distribution (sarge) this problem has been fixed in
version 1.4.1-1.sarge5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1140');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gnupg package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1140] DSA-1140-1 gnupg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1140-1 gnupg");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnupg', release: '3.1', reference: '1.4.1-1.sarge5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
