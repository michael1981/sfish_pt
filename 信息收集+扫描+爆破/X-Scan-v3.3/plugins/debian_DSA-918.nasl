# This script was automatically generated from the dsa-918
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22784);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "918");
 script_cve_id("CVE-2005-3346", "CVE-2005-3533");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-918 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in osh, the
operator\'s shell for executing defined programs in a privileged
environment.  The Common Vulnerabilities and Exposures project
identifies the following vulnerabilities:
CVE-2005-3346
    Charles Stevenson discovered a bug in the substitution of
    variables that allows a local attacker to open a root shell.
CVE-2005-3533
    Solar Eclipse discovered a buffer overflow caused by the current
    working directory plus a filename that could be used to execute
    arbitrary code and e.g. open a root shell.
For the old stable distribution (woody) these problems have been fixed in
version 1.7-11woody2.
For the stable distribution (sarge) these problems have been fixed in
version 1.7-13sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-918');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your osh package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA918] DSA-918-1 osh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-918-1 osh");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'osh', release: '3.0', reference: '1.7-11woody2');
deb_check(prefix: 'osh', release: '3.1', reference: '1.7-13sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
