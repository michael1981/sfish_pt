# This script was automatically generated from the dsa-1195
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22881);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1195");
 script_cve_id("CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1195 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple vulnerabilities have been discovered in the OpenSSL
cryptographic software package that could allow an attacker to launch
a denial of service attack by exhausting system resources or crashing
processes on a victim\'s computer.
CVE-2006-3738
        Tavis Ormandy and Will Drewry of the Google Security Team
        discovered a buffer overflow in SSL_get_shared_ciphers utility
        function, used by some applications such as exim and mysql.  An
        attacker could send a list of ciphers that would overrun a
        buffer.
CVE-2006-4343
        Tavis Ormandy and Will Drewry of the Google Security Team
        discovered a possible DoS in the sslv2 client code.  Where a
        client application uses OpenSSL to make a SSLv2 connection to
        a malicious server that server could cause the client to
        crash.
CVE-2006-2940
        Dr S N Henson of the OpenSSL core team and Open Network
        Security recently developed an ASN1 test suite for NISCC
        (www.niscc.gov.uk). When the test suite was run against
        OpenSSL a DoS was discovered.
        Certain types of public key can take disproportionate amounts
        of time to process. This could be used by an attacker in a
        denial of service attack.
For the stable distribution (sarge) these problems have been fixed in
version 0.9.6m-1sarge4.
This package exists only for compatibility with older software, and is
not present in the unstable or testing branches of Debian.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1195');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openssl096 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1195] DSA-1195-1 openssl096");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1195-1 openssl096");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libssl0.9.6', release: '3.1', reference: '0.9.6m-1sarge4');
deb_check(prefix: 'openssl096', release: '3.1', reference: '0.9.6m-1sarge4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
