# This script was automatically generated from the dsa-1581
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32403);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1581");
 script_cve_id("CVE-2008-1948", "CVE-2008-1949", "CVE-2008-1950");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1581 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in GNUTLS, an
implementation of the SSL/TLS protocol suite.
NOTE: The libgnutls13 package, which provides the GNUTLS library, does
not contain logic to automatically restart potentially affected
services.  You must restart affected services manually (mainly Exim,
using <q>/etc/init.d/exim4 restart</q>) after applying the update, to make
the changes fully effective.  Alternatively, you can reboot the system.
The Common Vulnerabilities and Exposures project identifies the following 
problems:
CVE-2008-1948
    A pre-authentication heap overflow involving oversized session
    resumption data may lead to arbitrary code execution.
CVE-2008-1949
    Repeated client hellos may result in a pre-authentication denial of
    service condition due to a null pointer dereference.
CVE-2008-1950
    Decoding cipher padding with an invalid record length may cause GNUTLS
    to read memory beyond the end of the received record, leading to a
    pre-authentication denial of service condition.
For the stable distribution (etch), these problems have been fixed in
version 1.4.4-3+etch1.  (Builds for the arm architecture are currently
not available and will be released later.)
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1581');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your GNUTLS packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1581] DSA-1581-1 gnutls13");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1581-1 gnutls13");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnutls-bin', release: '4.0', reference: '1.4.4-3+etch1');
deb_check(prefix: 'gnutls-doc', release: '4.0', reference: '1.4.4-3+etch1');
deb_check(prefix: 'libgnutls-dev', release: '4.0', reference: '1.4.4-3+etch1');
deb_check(prefix: 'libgnutls13', release: '4.0', reference: '1.4.4-3+etch1');
deb_check(prefix: 'libgnutls13-dbg', release: '4.0', reference: '1.4.4-3+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
