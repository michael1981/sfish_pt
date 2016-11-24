# This script was automatically generated from the dsa-093
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14930);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "093");
 script_cve_id("CVE-2001-0894");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-093 security update');
 script_set_attribute(attribute: 'description', value:
'Wietse Venema reported he found a denial of service vulnerability in
postfix. The SMTP session log that postfix keeps for debugging purposes
could grow to an unreasonable size.

This has been fixed in version 0.0.19991231pl11-2.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-093');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-093
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA093] DSA-093-1 postfix");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-093-1 postfix");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'postfix', release: '2.2', reference: '0.0.19991231pl11-2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
