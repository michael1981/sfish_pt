# This script was automatically generated from the dsa-091
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14928);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "091");
 script_cve_id("CVE-2001-0872");
 script_bugtraq_id(3614);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-091 security update');
 script_set_attribute(attribute: 'description', value:
'If the UseLogin feature is enabled in ssh local users could
pass environment variables (including variables like LD_PRELOAD)
to the login process. This has been fixed by not copying the
environment if UseLogin is enabled.

Please note that the default configuration for Debian does not
have UseLogin enabled.

This has been fixed in version 1:1.2.3-9.4.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-091');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-091
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA091] DSA-091-1 ssh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-091-1 ssh");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ssh', release: '2.2', reference: '1.2.3-9.4');
deb_check(prefix: 'ssh-askpass-gnome', release: '2.2', reference: '1.2.3-9.4');
deb_check(prefix: 'ssh-askpass-ptk', release: '2.2', reference: '1.2.3-9.4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
