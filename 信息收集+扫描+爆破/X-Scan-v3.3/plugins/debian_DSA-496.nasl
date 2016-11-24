# This script was automatically generated from the dsa-496
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15333);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "496");
 script_cve_id("CVE-2003-0068");
 script_bugtraq_id(10237);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-496 security update');
 script_set_attribute(attribute: 'description', value:
'H.D. Moore discovered several terminal emulator security issues.  One
of them covers escape codes that are interpreted by the terminal
emulator.  This could be exploited by an attacker to insert malicious
commands hidden for the user, who has to hit enter to continue, which
would also execute the hidden commands.
For the stable distribution (woody) this problem has been fixed in
version 0.9.2-0pre2002042903.3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-496');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your eterm package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA496] DSA-496-1 eterm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-496-1 eterm");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'eterm', release: '3.0', reference: '0.9.2-0pre2002042903.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
