# This script was automatically generated from the dsa-1027
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22569);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1027");
 script_cve_id("CVE-2006-0052");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1027 security update');
 script_set_attribute(attribute: 'description', value:
'A potential denial of service problem has been discovered in mailman,
the web-based GNU mailing list manager.  The (failing) parsing of
messages with malformed mime multiparts sometimes caused the whole
mailing list to become inoperative.
The old stable distribution (woody) is not vulnerable to this issue.
For the stable distribution (sarge) this problem has been fixed in
version 2.1.5-8sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1027');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mailman package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1027] DSA-1027-1 mailman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1027-1 mailman");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mailman', release: '3.1', reference: '2.1.5-8sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
