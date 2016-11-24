# This script was automatically generated from the dsa-1795
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38723);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1795");
 script_cve_id("CVE-2009-1086");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1795 security update');
 script_set_attribute(attribute: 'description', value:
'Stefan Kaltenbrunner discovered that ldns, a library and set of utilities
to facilitate DNS programming, did not correctly implement a buffer
boundary check in its RR DNS record parser.  This weakness could enable
overflow of a heap buffer if a maliciously-crafted record is parsed,
potentially allowing the execution of arbitrary code.  The scope of
compromise will vary with the context in which ldns is used, and could
present either a local or remote attack vector.
The old stable distribution (etch) is not affected by this issue.
For the stable distribution (lenny), this problem has been fixed in
version 1.4.0-1+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1795');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ldns packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1795] DSA-1795-1 ldns");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1795-1 ldns");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ldnsutils', release: '5.0', reference: '1.4.0-1+lenny1');
deb_check(prefix: 'libldns-dev', release: '5.0', reference: '1.4.0-1+lenny1');
deb_check(prefix: 'libldns1', release: '5.0', reference: '1.4.0-1+lenny1');
deb_check(prefix: 'ldns', release: '5.0', reference: '1.4.0-1+lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
