# This script was automatically generated from the dsa-1735
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35901);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1735");
 script_cve_id("CVE-2009-0759");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1735 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that znc, an IRC proxy/bouncer, does not properly
sanitize input contained in configuration change requests to the
webadmin interface.  This allows authenticated users to elevate their
privileges and indirectly execute arbitrary commands (CVE-2009-0759).
For the old stable distribution (etch), this problem has been fixed in
version 0.045-3+etch2.
For the stable distribution (lenny), this problem has been fixed in
version 0.058-2+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1735');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your znc packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1735] DSA-1735-1 znc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1735-1 znc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'znc', release: '4.0', reference: '0.058-2+lenny1');
deb_check(prefix: 'znc', release: '4.0', reference: '0.045-3+etch2');
deb_check(prefix: 'znc', release: '5.0', reference: '0.058-2+lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
