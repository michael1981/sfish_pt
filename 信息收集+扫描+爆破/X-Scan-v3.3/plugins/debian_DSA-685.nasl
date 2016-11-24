# This script was automatically generated from the dsa-685
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(17130);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "685");
 script_cve_id("CVE-2005-0100");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-685 security update');
 script_set_attribute(attribute: 'description', value:
'Max Vozeler discovered several format string vulnerabilities in the
movemail utility of Emacs, the well-known editor.  Via connecting to a
malicious POP server an attacker can execute arbitrary code under the
privileges of group mail.
For the stable distribution (woody) these problems have been fixed in
version 21.2-1woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-685');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your emacs packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA685] DSA-685-1 emacs21");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-685-1 emacs21");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'emacs21', release: '3.0', reference: '21.2-1woody3');
deb_check(prefix: 'emacs21-el', release: '3.0', reference: '21.2-1woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
