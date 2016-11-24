# This script was automatically generated from the dsa-211
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15048);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "211");
 script_cve_id("CVE-2002-1362");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-211 security update');
 script_set_attribute(attribute: 'description', value:
'Rüdiger Kuhlmann, upstream developer of mICQ, a text based ICQ client,
discovered a problem in mICQ.  Receiving certain ICQ message types
that do not contain the required 0xFE separator causes all versions to
crash.
For the current stable distribution (woody) this problem has been
fixed in version 0.4.9-0woody3.
For the old stable distribution (potato) this problem has been fixed
in version 0.4.3-4.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-211');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your micq package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA211] DSA-211-1 micq");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-211-1 micq");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'micq', release: '2.2', reference: '0.4.3-4.1');
deb_check(prefix: 'micq', release: '3.0', reference: '0.4.9-0woody3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
