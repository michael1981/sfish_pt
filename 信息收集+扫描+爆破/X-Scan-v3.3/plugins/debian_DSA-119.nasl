# This script was automatically generated from the dsa-119
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14956);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "119");
 script_cve_id("CVE-2002-0083");
 script_bugtraq_id(4241);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-119 security update');
 script_set_attribute(attribute: 'description', value:
'Joost Pol reports that OpenSSH
versions 2.0 through 3.0.2 have an off-by-one bug in the channel allocation
code. This vulnerability can be exploited by authenticated users to gain
root privilege or by a malicious server exploiting a client with this
bug.
Since Debian 2.2 (potato) shipped with OpenSSH (the "ssh" package)
version 1.2.3, it is not vulnerable to this exploit. No fix is required
for Debian 2.2 (potato).
The Debian unstable and testing archives do include a more recent OpenSSH
(ssh) package. If you are running these pre-release distributions you should
ensure that you are running version 3.0.2p1-8, a patched version which was
added to the unstable archive today, or a later version.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-119');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-119
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA119] DSA-119-1 ssh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-119-1 ssh");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
