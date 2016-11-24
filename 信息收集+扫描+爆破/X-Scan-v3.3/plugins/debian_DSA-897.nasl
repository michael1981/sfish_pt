# This script was automatically generated from the dsa-897
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22763);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "897");
 script_cve_id("CVE-2005-0870", "CVE-2005-3347", "CVE-2005-3348");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-897 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in phpsysinfo, a PHP
based host information application.  The Common Vulnerabilities and
Exposures project identifies the following problems: 
CVE-2005-0870
    Maksymilian Arciemowicz discovered several cross site scripting
    problems, of which not all were fixed in DSA 724.
CVE-2005-3347
    Christopher Kunz discovered that local variables get overwritten
    unconditionally and are trusted later, which could lead to the
    inclusion of arbitrary files.
CVE-2005-3348
    Christopher Kunz discovered that user-supplied input is used
    unsanitised, causing a HTTP Response splitting problem.
For the old stable distribution (woody) these problems have been fixed in
version 2.0-3woody3.
For the stable distribution (sarge) these problems have been fixed in
version 2.3-4sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-897');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpsysinfo package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA897] DSA-897-1 phpsysinfo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-897-1 phpsysinfo");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpsysinfo', release: '3.0', reference: '2.0-3woody3');
deb_check(prefix: 'phpsysinfo', release: '3.1', reference: '2.3-4sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
