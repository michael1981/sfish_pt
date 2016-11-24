# This script was automatically generated from the dsa-1685
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35091);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1685");
 script_cve_id("CVE-2008-5005", "CVE-2008-5006");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1685 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been found in uw-imap, an IMAP
implementation. The Common Vulnerabilities and Exposures project
identifies the following problems:
It was discovered that several buffer overflows can be triggered via a
long folder extension argument to the tmail or dmail program. This
could lead to arbitrary code execution (CVE-2008-5005).
It was discovered that a NULL pointer dereference could be triggered by
a malicious response to the QUIT command leading to a denial of service
(CVE-2008-5006).
For the stable distribution (etch), these problems have been fixed in
version 2002edebian1-13.1+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1685');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your uw-imap packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1685] DSA-1685-1 uw-imap");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1685-1 uw-imap");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ipopd', release: '4.0', reference: '2002edebian1-13.1+etch1');
deb_check(prefix: 'ipopd-ssl', release: '4.0', reference: '2002edebian1-13.1+etch1');
deb_check(prefix: 'libc-client-dev', release: '4.0', reference: '2002edebian1-13.1+etch1');
deb_check(prefix: 'libc-client2002edebian', release: '4.0', reference: '2002edebian1-13.1+etch1');
deb_check(prefix: 'mlock', release: '4.0', reference: '2002edebian1-13.1+etch1');
deb_check(prefix: 'uw-imapd', release: '4.0', reference: '2002edebian1-13.1+etch1');
deb_check(prefix: 'uw-imapd-ssl', release: '4.0', reference: '2002edebian1-13.1+etch1');
deb_check(prefix: 'uw-mailutils', release: '4.0', reference: '2002edebian1-13.1+etch1');
deb_check(prefix: 'uw-imap', release: '4.0', reference: '2002edebian1-13.1+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
