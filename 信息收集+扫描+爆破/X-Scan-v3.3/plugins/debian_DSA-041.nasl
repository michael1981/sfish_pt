# This script was automatically generated from the dsa-041
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14878);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "041");
 script_cve_id("CVE-2001-0289");
 script_bugtraq_id(2437);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-041 security update');
 script_set_attribute(attribute: 'description', value:
'Christer Öberg of Wkit Security AB found a problem in joe
(Joe\'s Own Editor). joe will look for a configuration file in three locations:
The current directory, the users homedirectory ($HOME) and in /etc/joe. Since
the configuration file can define commands joe will run (for example to check
spelling) reading it from the current directory can be dangerous: An attacker
can leave a .joerc file in a writable directory, which would be read when a
unsuspecting user starts joe in that directory.

This has been fixed in version 2.8-15.3 and we recommend that you upgrade
your joe package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-041');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-041
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA041] DSA-041-1 joe");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-041-1 joe");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'joe', release: '2.2', reference: '2.8-15.3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
