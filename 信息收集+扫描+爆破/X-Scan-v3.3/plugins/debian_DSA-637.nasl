# This script was automatically generated from the dsa-637
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16155);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "637");
 script_cve_id("CVE-2005-0021");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-637 security update');
 script_set_attribute(attribute: 'description', value:
'Philip Hazel announced a buffer overflow in the host_aton function in
exim-tls, the SSL-enabled version of the default mail-transport-agent
in Debian, which can lead to the execution of arbitrary code via an
illegal IPv6 address.
For the stable distribution (woody) this problem has been fixed in
version 3.35-3woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-637');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your exim-tls package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA637] DSA-637-1 exim-tls");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-637-1 exim-tls");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'exim-tls', release: '3.0', reference: '3.35-3woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
