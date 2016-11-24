# This script was automatically generated from the dsa-329
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15166);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "329");
 script_cve_id("CVE-2003-0452");
 script_bugtraq_id(7992, 7993);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-329 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp discovered that osh, a shell intended to restrict the
actions of the user, contains two buffer overflows, in processing
environment variables and file redirections.  These vulnerabilities
could be used to execute arbitrary code, overriding any restrictions
placed on the shell.
For the stable distribution (woody) this problem has been fixed in
version 1.7-11woody1.
The old stable distribution (potato) is affected by this problem, and
may be fixed in a future advisory on a time-available basis.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-329');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-329
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA329] DSA-329-1 osh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-329-1 osh");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'osh', release: '3.0', reference: '1.7-11woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
