# This script was automatically generated from the dsa-090
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14927);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "090");
 script_cve_id("CVE-2002-0334");
 script_bugtraq_id(3626);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-090 security update');
 script_set_attribute(attribute: 'description', value:
'The xtel (an X emulator for minitel) package as distributed with Debian
GNU/Linux 2.2 has two possible symlink attacks:
Both problems have been fixed in version 3.2.1-4.potato.1 .

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-090');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-090
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA090] DSA-090-1 xtel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-090-1 xtel");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xtel', release: '2.2', reference: '3.2.1-4.potato.1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
