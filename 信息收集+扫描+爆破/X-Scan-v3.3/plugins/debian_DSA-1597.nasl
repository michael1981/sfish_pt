# This script was automatically generated from the dsa-1597
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33178);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1597");
 script_cve_id("CVE-2007-5824", "CVE-2007-5825", "CVE-2008-1771");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1597 security update');
 script_set_attribute(attribute: 'description', value:
'Three vulnerabilities have been discovered in the mt-daapd DAAP audio
server (also known as the Firefly Media Server).  The Common
Vulnerabilities and Exposures project identifies the following three
problems:
CVE-2007-5824
    Insufficient validation and bounds checking of the Authorization:
    HTTP header enables a heap buffer overflow, potentially enabling
    the execution of arbitrary code.
CVE-2007-5825
    Format string vulnerabilities in debug logging within the
    authentication of XML-RPC requests could enable the execution of
    arbitrary code.
CVE-2008-1771
    An integer overflow weakness in the handling of HTTP POST
    variables could allow a heap buffer overflow and potentially
    arbitrary code execution.
For the stable distribution (etch), these problems have been fixed in
version 0.2.4+r1376-1.1+etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1597');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mt-daapd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1597] DSA-1597-2 mt-daapd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1597-2 mt-daapd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mt-daapd', release: '4.0', reference: '0.2.4+r1376-1.1+etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
