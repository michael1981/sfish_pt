# This script was automatically generated from the dsa-025
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14862);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "025");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-025 security update');
 script_set_attribute(attribute: 'description', value:
'A former security upload of OpenSSH lacked support for PAM
which lead to people not being able to log onto their server. This was
only a problem on the sparc architecture. We recommend you
upgrade your ssh packages on sparc.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-025');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-025
and install the recommended updated packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA025] DSA-025-2 openssh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-025-2 openssh");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ssh', release: '2.2', reference: '1.2.3-9.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
