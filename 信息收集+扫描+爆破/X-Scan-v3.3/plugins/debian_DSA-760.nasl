# This script was automatically generated from the dsa-760
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19223);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "760");
 script_cve_id("CVE-2005-1850", "CVE-2005-1851", "CVE-2005-1916");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-760 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in ekg, a console Gadu
Gadu client, an instant messaging program.  The Common Vulnerabilities
and Exposures project identifies the following vulnerabilities:
    Marcin Owsiany and Wojtek Kaniewski discovered insecure temporary
    file creation in contributed scripts.
    Marcin Owsiany and Wojtek Kaniewski discovered potential shell
    command injection in a contributed script.
    Eric Romang discovered insecure temporary file creation and
    arbitrary command execution in a contributed script that can be
    exploited by a local attacker.
The old stable distribution (woody) does not contain an ekg package.
For the stable distribution (sarge) these problems have been fixed in
version 1.5+20050411-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-760');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ekg package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA760] DSA-760-1 ekg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-760-1 ekg");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ekg', release: '3.1', reference: '1.5+20050411-4');
deb_check(prefix: 'libgadu-dev', release: '3.1', reference: '1.5+20050411-4');
deb_check(prefix: 'libgadu3', release: '3.1', reference: '1.5+20050411-4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
