# This script was automatically generated from the dsa-843
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19847);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "843");
 script_cve_id("CVE-2005-2945", "CVE-2005-2992");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-843 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been discovered in the ARC archive program
under Unix.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Eric Romang discovered that the ARC archive program under Unix
    creates a temporary file with insecure permissions which may lead
    to an attacker stealing sensitive information.
    Joey Schulze discovered that the temporary file was created in an
    insecure fashion as well, leaving it open to a classic symlink
    attack.
The old stable distribution (woody) does not contain arc packages.
For the stable distribution (sarge) these problems have been fixed in
version 5.21l-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-843');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your arc package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA843] DSA-843-1 arc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-843-1 arc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'arc', release: '3.1', reference: '5.21l-1sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
