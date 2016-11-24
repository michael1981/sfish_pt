# This script was automatically generated from the dsa-209
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15046);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "209");
 script_cve_id("CVE-2002-1344", "CVE-2002-1565");
 script_bugtraq_id(6352);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-209 security update');
 script_set_attribute(attribute: 'description', value:
'Two problems have been found in the wget package as distributed in
Debian GNU/Linux:
Both problems have been fixed in version 1.5.3-3.1 for Debian GNU/Linux
2.2/potato and version 1.8.1-6.1 for Debian GNU/Linux 3.0/woody.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-209');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-209
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA209] DSA-209-1 wget");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-209-1 wget");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wget', release: '2.2', reference: '1.5.3-3.1');
deb_check(prefix: 'wget', release: '3.0', reference: '1.8.1-6.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
