# This script was automatically generated from the dsa-1734
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35790);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1734");
 script_cve_id("CVE-2009-0368");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1734 security update');
 script_set_attribute(attribute: 'description', value:
'b.badrignans discovered that OpenSC, a set of smart card utilities,
could stores private data on a smart card without proper access
restrictions.
Only blank cards initialised with OpenSC are affected by this problem.
This update only improves creating new private data objects, but cards
already initialised with such private data objects need to be
modified to repair the access control conditions on such cards.
Instructions for a variety of situations can be found at the OpenSC
web site: http://www.opensc-project.org/security.html
The oldstable distribution (etch) is not affected by this problem.
For the stable distribution (lenny), this problem has been fixed in
version 0.11.4-5+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1734');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your opensc package and recreate any
private data objects stored on your smart cards.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1734] DSA-1734-1 opensc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1734-1 opensc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libopensc2', release: '5.0', reference: '0.11.4-5+lenny1');
deb_check(prefix: 'libopensc2-dbg', release: '5.0', reference: '0.11.4-5+lenny1');
deb_check(prefix: 'libopensc2-dev', release: '5.0', reference: '0.11.4-5+lenny1');
deb_check(prefix: 'mozilla-opensc', release: '5.0', reference: '0.11.4-5+lenny1');
deb_check(prefix: 'opensc', release: '5.0', reference: '0.11.4-5+lenny1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
