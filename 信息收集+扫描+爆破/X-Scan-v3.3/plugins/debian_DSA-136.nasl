# This script was automatically generated from the dsa-136
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14973);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "136");
 script_cve_id("CVE-2002-0655", "CVE-2002-0656", "CVE-2002-0657", "CVE-2002-0659");
 script_bugtraq_id(5353, 5361, 5362, 5363, 5364, 5366);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-136 security update');
 script_set_attribute(attribute: 'description', value:
'The OpenSSL development team has announced that a security audit by A.L.
Digital Ltd and The Bunker, under the DARPA CHATS program, has revealed
remotely exploitable buffer overflow conditions in the OpenSSL code.
Additionally, the ASN1 parser in OpenSSL has a potential DoS attack
independently discovered by Adi Stav and James Yonan.
CVE-2002-0655 references overflows in buffers used to hold ASCII
representations of integers on 64 bit platforms. CVE-2002-0656
references buffer overflows in the SSL2 server implementation (by
sending an invalid key to the server) and the SSL3 client implementation
(by sending a large session id to the client). The SSL2 issue was also
noticed by Neohapsis, who have privately demonstrated exploit code for
this issue. CVE-2002-0659 references the ASN1 parser DoS issue.
These vulnerabilities have been addressed for Debian 3.0 (woody) in
openssl094_0.9.4-6.woody.2, openssl095_0.9.5a-6.woody.1 and
openssl_0.9.6c-2.woody.1.
These vulnerabilities are also present in Debian 2.2 (potato). Fixed
packages are available in openssl094_0.9.4-6.potato.2 and
openssl_0.9.6c-0.potato.4.
A worm is actively exploiting this issue on internet-attached hosts;
we recommend you upgrade your OpenSSL as soon as possible. Note that you
must restart any daemons using SSL. (E.g., ssh or ssl-enabled apache.)
If you are uncertain which programs are using SSL you may choose to
reboot to ensure that all running daemons are using the new libraries.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-136');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-136
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA136] DSA-136-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-136-1 openssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libssl-dev', release: '2.2', reference: '0.9.6c-0.potato.4');
deb_check(prefix: 'libssl0.9.6', release: '2.2', reference: '0.9.6c-0.potato.4');
deb_check(prefix: 'libssl09', release: '2.2', reference: '0.9.4-6.potato.2');
deb_check(prefix: 'openssl', release: '2.2', reference: '0.9.6c-0.potato.4');
deb_check(prefix: 'ssleay', release: '2.2', reference: '0.9.6c-0.potato.3');
deb_check(prefix: 'libssl-dev', release: '3.0', reference: '0.9.6c-2.woody.1');
deb_check(prefix: 'libssl0.9.6', release: '3.0', reference: '0.9.6c-2.woody.1');
deb_check(prefix: 'libssl09', release: '3.0', reference: '0.9.4-6.woody.1');
deb_check(prefix: 'libssl095a', release: '3.0', reference: '0.9.5a-6.woody.1');
deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
