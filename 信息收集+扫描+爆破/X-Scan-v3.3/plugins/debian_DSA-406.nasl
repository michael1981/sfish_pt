# This script was automatically generated from the dsa-406
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15243);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "406");
 script_cve_id("CVE-2003-0963");
 script_bugtraq_id(9210);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-406 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar discovered a buffer overflow in lftp, a set of
sophisticated command-line FTP/HTTP client programs.  An attacker
could create a carefully crafted directory on a website so that the
execution of an \'ls\' or \'rels\' command would lead to the execution of
arbitrary code on the client machine.
For the stable distribution (woody) this problem has been fixed in
version 2.4.9-1woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-406');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-406
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA406] DSA-406-1 lftp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-406-1 lftp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lftp', release: '3.0', reference: '2.4.9-1woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
