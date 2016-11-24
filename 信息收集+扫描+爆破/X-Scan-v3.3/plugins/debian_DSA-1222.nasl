# This script was automatically generated from the dsa-1222
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23757);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1222");
 script_cve_id("CVE-2006-5815", "CVE-2006-6170", "CVE-2006-6171");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1222 security update');
 script_set_attribute(attribute: 'description', value:
'Due to technical problems yesterday\'s proftpd update lacked a build for
the amd64 architecture, which is now available. For reference please find
below the original advisory text:
Several remote vulnerabilities have been discovered in the proftpd FTP
daemon, which may lead to the execution of arbitrary code or denial
of service. The Common Vulnerabilities and Exposures project identifies
the following problems:
CVE-2006-5815
    It was discovered that a buffer overflow in the sreplace() function
    may lead to denial of service and possibly the execution of arbitrary
    code.
CVE-2006-6170
    It was discovered that a buffer overflow in the mod_tls addon module
    may lead to the execution of arbitrary code.
CVE-2006-6171
    It was discovered that insufficient validation of FTP command buffer
    size limits may lead to denial of service. Due to unclear information
    this issue was already fixed in DSA-1218 as CVE-2006-5815.
For the stable distribution (sarge) these problems have been fixed in version
1.2.10-15sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1222');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your proftpd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1222] DSA-1222-2 proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1222-2 proftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'proftpd', release: '3.1', reference: '1.2.10-15sarge3');
deb_check(prefix: 'proftpd-common', release: '3.1', reference: '1.2.10-15sarge3');
deb_check(prefix: 'proftpd-doc', release: '3.1', reference: '1.2.10-15sarge3');
deb_check(prefix: 'proftpd-ldap', release: '3.1', reference: '1.2.10-15sarge3');
deb_check(prefix: 'proftpd-mysql', release: '3.1', reference: '1.2.10-15sarge3');
deb_check(prefix: 'proftpd-pgsql', release: '3.1', reference: '1.2.10-15sarge3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
