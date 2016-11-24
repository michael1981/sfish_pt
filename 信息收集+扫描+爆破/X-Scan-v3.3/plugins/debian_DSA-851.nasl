# This script was automatically generated from the dsa-851
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19959);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "851");
 script_cve_id("CVE-2005-2531", "CVE-2005-2532", "CVE-2005-2533", "CVE-2005-2534");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-851 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in openvpn, a
Virtual Private Network daemon.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Wrong processing of failed certificate authentication when running
    with "verb 0" and without TLS authentication can lead to a denial
    of service by disconnecting the wrong client.
    Wrong handling of packets that can\'t be decrypted on the server
    can lead to the disconnection of unrelated clients.
    When running in "dev tap" Ethernet bridging mode, openvpn can
    exhaust its memory by receiving a large number of spoofed MAC
    addresses and hence denying service.
    Simultaneous TCP connections from multiple clients with the same
    client certificate can cause a denial of service when
    --duplicate-cn is not enabled.
The old stable distribution (woody) does not contain openvpn packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.0-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-851');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openvpn package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA851] DSA-851-1 openvpn");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-851-1 openvpn");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'openvpn', release: '3.1', reference: '2.0-1sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
