# This script was automatically generated from the dsa-1467
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30023);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1467");
 script_cve_id("CVE-2006-6574", "CVE-2007-6611");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1467 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Mantis, a web based
bug tracking system. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2006-6574
    Custom fields were not appropriately protected by per-item access
    control, allowing for sensitive data to be published.
CVE-2007-6611
    Multiple cross site scripting issues allowed a remote attacker to
    insert malicious HTML or web script into Mantis web pages.
For the old stable distribution (sarge), these problems have been fixed in
version 0.19.2-5sarge5.
The stable distribution (etch) is not affected by these problems.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1467');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mantis package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1467] DSA-1467-1 mantis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1467-1 mantis");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mantis', release: '3.1', reference: '0.19.2-5sarge5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
