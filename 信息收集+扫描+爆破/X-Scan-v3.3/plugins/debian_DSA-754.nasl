# This script was automatically generated from the dsa-754
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19188);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "754");
 script_cve_id("CVE-2005-1914");
 script_bugtraq_id(14144);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-754 security update');
 script_set_attribute(attribute: 'description', value:
'Eric Romang discovered that centericq, a text-mode multi-protocol
instant messenger client, creates some temporary files with
predictable filenames and is hence vulnerable to symlink attacks by
local attackers.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 4.20.0-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-754');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your centericq package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA754] DSA-754-1 centericq");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-754-1 centericq");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'centericq', release: '3.1', reference: '4.20.0-1sarge1');
deb_check(prefix: 'centericq-common', release: '3.1', reference: '4.20.0-1sarge1');
deb_check(prefix: 'centericq-fribidi', release: '3.1', reference: '4.20.0-1sarge1');
deb_check(prefix: 'centericq-utf8', release: '3.1', reference: '4.20.0-1sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
