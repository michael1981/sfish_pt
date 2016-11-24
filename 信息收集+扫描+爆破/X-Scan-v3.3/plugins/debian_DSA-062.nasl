# This script was automatically generated from the dsa-062
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14899);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "062");
 script_cve_id("CVE-2001-1077");
 script_bugtraq_id(2878);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-062 security update');
 script_set_attribute(attribute: 'description', value:
'Samuel Dralet reported on bugtraq that version 2.6.2 of rxvt (a
VT102 terminal emulator for X) have a buffer overflow in the
tt_printf() function. A local user could abuse this making rxvt
print a special string using that function, for example by using
the -T or -name command-line options.
That string would cause a
stack overflow and contain code which rxvt will execute.

Since rxvt is installed sgid utmp an attacker could use this
to gain utmp which would allow them to modify the utmp file.

This has been fixed in version 2.6.2-2.1, and we recommend that
you upgrade your rxvt package.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-062');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-062
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA062] DSA-062-1 rxvt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-062-1 rxvt");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'rxvt', release: '2.2', reference: '2.6.2-2.1');
deb_check(prefix: 'rxvt-ml', release: '2.2', reference: '2.6.2-2.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
