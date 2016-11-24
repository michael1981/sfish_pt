# This script was automatically generated from the dsa-762
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19225);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "762");
 script_cve_id("CVE-2005-2250", "CVE-2005-2277");
 script_bugtraq_id(14230);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-762 security update');
 script_set_attribute(attribute: 'description', value:
'Kevin Finisterre discovered two problems in the Bluetooth FTP client
from affix, user space utilities for the Affix Bluetooth protocol
stack.  The Common Vulnerabilities and Exposures project identifies
the following vulnerabilities:
    A buffer overflow allows remote attackers to execute arbitrary
    code via a long filename in an OBEX file share.
    Missing input sanitising before executing shell commands allow an
    attacker to execute arbitrary commands as root.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 2.1.1-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-762');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your affix package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA762] DSA-762-1 affix");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-762-1 affix");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'affix', release: '3.1', reference: '2.1.1-2');
deb_check(prefix: 'libaffix-dev', release: '3.1', reference: '2.1.1-2');
deb_check(prefix: 'libaffix2', release: '3.1', reference: '2.1.1-2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
