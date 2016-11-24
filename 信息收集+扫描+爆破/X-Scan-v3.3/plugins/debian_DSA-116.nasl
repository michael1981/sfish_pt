# This script was automatically generated from the dsa-116
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14953);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "116");
 script_cve_id("CVE-2002-0351");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-116 security update');
 script_set_attribute(attribute: 'description', value:
'Zorgon found several buffer overflows in cfsd, a daemon that pushes
encryption services into the Unix(tm) file system.  We are not yet
sure if these overflows can successfully be exploited to gain root
access to the machine running the CFS daemon.  However, since cfsd can
easily be forced to die, a malicious user can easily perform a denial
of service attack to it.
This problem has been fixed in version 1.3.3-8.1 for the stable Debian
distribution and in version 1.4.1-5 for the testing and unstable
distribution of Debian.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-116');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cfs package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA116] DSA-116-1 cfs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-116-1 cfs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cfs', release: '2.2', reference: '1.3.3-8.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
