# This script was automatically generated from the dsa-313
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15150);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "313");
 script_cve_id("CVE-2003-0356", "CVE-2003-0357");
 script_bugtraq_id(7493, 7494, 7495);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-313 security update');
 script_set_attribute(attribute: 'description', value:
'Timo Sirainen discovered several vulnerabilities in ethereal, a
network traffic analyzer.  These include one-byte buffer overflows in
the AIM, GIOP Gryphon, OSPF, PPTP, Quake, Quake2, Quake3, Rsync, SMB,
SMPP, and TSP dissectors, and integer overflows in the Mount and PPP
dissectors.
For the stable distribution (woody) these problems have been fixed in
version 0.9.4-1woody4.
The old stable distribution (potato) does not appear to contain these
vulnerabilities.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-313');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-313
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA313] DSA-313-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-313-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody4');
deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody4');
deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody4');
deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
