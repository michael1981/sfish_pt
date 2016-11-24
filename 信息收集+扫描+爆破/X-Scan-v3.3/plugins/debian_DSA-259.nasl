# This script was automatically generated from the dsa-259
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15096);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "259");
 script_cve_id("CVE-2003-0143");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-259 security update');
 script_set_attribute(attribute: 'description', value:
'Florian Heinz heinz@cronon-ag.de posted to the Bugtraq mailing list an
exploit for qpopper based on a bug in the included vsnprintf implementation.
The sample exploit requires a valid user account and password, and overflows a
string in the pop_msg() function to give the user "mail" group privileges and a
shell on the system. Since the Qvsnprintf function is used elsewhere in
qpopper, additional exploits may be possible.
The qpopper package in Debian 2.2 (potato) does not include the vulnerable
snprintf implementation. For Debian 3.0 (woody) an updated package is available
in version 4.0.4-2.woody.3. Users running an unreleased version of Debian
should upgrade to 4.0.4-9 or newer. We recommend you upgrade your qpopper
package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-259');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-259
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA259] DSA-259-1 qpopper");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-259-1 qpopper");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'qpopper', release: '3.0', reference: '4.0.4-2.woody.3');
deb_check(prefix: 'qpopper-drac', release: '3.0', reference: '4.0.4-2.woody.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
