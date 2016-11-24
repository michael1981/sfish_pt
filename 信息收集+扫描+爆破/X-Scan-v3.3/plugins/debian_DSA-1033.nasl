# This script was automatically generated from the dsa-1033
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22575);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1033");
 script_cve_id("CVE-2005-4190", "CVE-2006-1260", "CVE-2006-1491");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1033 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Horde web
application framework, which may lead to the execution of arbitrary 
web script code. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2005-4190
    Several Cross-Site-Scripting vulnerabilities have been discovered in
    the "share edit window".
CVE-2006-1260
    Null characters in the URL parameter bypass a sanity check, which
    allowed remote attackers to read arbitrary files, which allowed
    information disclosure.
CVE-2006-1491
    User input in the help viewer was passed unsanitised to the eval()
    function, which allowed injection of arbitrary web code.
The old stable distribution (woody) doesn\'t contain horde3 packages.
For the stable distribution (sarge) these problems have been fixed in
version 3.0.4-4sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1033');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your horde3 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1033] DSA-1033-1 horde3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1033-1 horde3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'horde3', release: '3.1', reference: '3.0.4-4sarge3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
