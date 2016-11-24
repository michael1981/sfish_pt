# This script was automatically generated from the dsa-376
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15213);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "376");
 script_cve_id("CVE-2003-0743");
 script_bugtraq_id(8518);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-376 security update');
 script_set_attribute(attribute: 'description', value:
'A buffer overflow exists in exim, which is the standard mail transport
agent in Debian.  By supplying a specially crafted HELO or EHLO
command, an attacker could cause a constant string to be written past
the end of a buffer allocated on the heap.  This vulnerability is not
believed at this time to be exploitable to execute arbitrary code.
For the stable distribution (woody) this problem has been fixed in
exim version 3.35-1woody2 and exim-tls version 3.35-3woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-376');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-376
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA376] DSA-376-2 exim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-376-2 exim");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'exim', release: '3.0', reference: '3.35-1woody2');
deb_check(prefix: 'exim-tls', release: '3.0', reference: '3.35-3woody1');
deb_check(prefix: 'eximon', release: '3.0', reference: '3.35-1woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
