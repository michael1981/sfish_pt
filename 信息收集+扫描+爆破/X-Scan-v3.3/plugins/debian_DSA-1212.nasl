# This script was automatically generated from the dsa-1212
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23661);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1212");
 script_cve_id("CVE-2006-4924", "CVE-2006-5051");
 script_bugtraq_id(20216, 20241);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1212 security update');
 script_set_attribute(attribute: 'description', value:
'Two denial of service problems have been found in the OpenSSH
server. The Common Vulnerabilities and Exposures project identifies the
following vulnerabilities:
CVE-2006-4924
    The sshd support for ssh protocol version 1 does not properly
    handle duplicate incoming blocks. This could allow a remote
    attacker to cause sshd to consume significant CPU resources
    leading to a denial of service.
CVE-2006-5051
    A signal handler race condition could potentially allow a remote
    attacker to crash sshd and could theoretically lead to the
    ability to execute arbitrary code.
For the stable distribution (sarge), these problems have been fixed in
version 1:3.8.1p1-8.sarge.6.
For the unstable and testing distributions, these problems have been
fixed in version 1:4.3p2-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1212');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openssh package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1212] DSA-1212-1 openssh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1212-1 openssh");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ssh', release: '3.1', reference: '3.8.1p1-8.sarge.6');
deb_check(prefix: 'ssh-askpass-gnome', release: '3.1', reference: '3.8.1p1-8.sarge.6');
deb_check(prefix: 'openssh', release: '3.1', reference: '3.8.1p1-8.sarge.6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
