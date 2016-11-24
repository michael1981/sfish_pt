# This script was automatically generated from the dsa-995
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22861);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "995");
 script_cve_id("CVE-2006-0709");
 script_bugtraq_id(16611);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-995 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar discovered a buffer overflow in metamail, an
implementation of MIME (Multi-purpose Internet Mail Extensions), that
could lead to a denial of service or potentially execute arbitrary
code when processing messages.
For the old stable distribution (woody) this problem has been fixed in
version 2.7-45woody.4.
For the stable distribution (sarge) this problem has been fixed in
version 2.7-47sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-995');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your metamail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA995] DSA-995-1 metamail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-995-1 metamail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'metamail', release: '3.0', reference: '2.7-45woody.4');
deb_check(prefix: 'metamail', release: '3.1', reference: '2.7-47sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
