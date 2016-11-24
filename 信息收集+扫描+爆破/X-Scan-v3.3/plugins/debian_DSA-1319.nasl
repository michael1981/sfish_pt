# This script was automatically generated from the dsa-1319
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25585);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1319");
 script_cve_id("CVE-2007-3114", "CVE-2007-3115", "CVE-2007-3116");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1319 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in MaraDNS, a simple
security-aware Domain Name Service server. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2007-3114
    It was discovered that malformed DNS requests can trigger memory
    leaks, allowing denial of service.
CVE-2007-3115
    It was discovered that malformed DNS requests can trigger memory
    leaks, allowing denial of service.
CVE-2007-3116
    It was discovered that malformed DNS requests can trigger memory
    leaks, allowing denial of service.
The oldstable distribution (sarge) is not affected by these problems.
For the stable distribution (etch) these problems have been fixed
in version 1.2.12.04-1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1319');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your maradns packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1319] DSA-1319-1 maradns");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1319-1 maradns");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'maradns', release: '4.0', reference: '1.2.12.04-1etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
