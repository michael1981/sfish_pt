# This script was automatically generated from the dsa-509
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15346);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "509");
 script_cve_id("CVE-2004-0395");
 script_bugtraq_id(10437);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-509 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp discovered a vulnerability in xatitv, one of the programs
in the gatos package, which is used to display video with certain
ATI video cards.
xatitv is installed setuid root in order to gain direct access to the
video hardware.  It normally drops root privileges after successfully
initializing itself.  However, if initialization fails due to a
missing configuration file, root privileges are not dropped, and
xatitv executes the system(3) function to launch its configuration
program without sanitizing user-supplied environment variables.
By exploiting this vulnerability, a local user could gain root
privileges if the configuration file does not exist.  However, a
default configuration file is supplied with the package, and so this
vulnerability is not exploitable unless this file is removed by the
administrator.
For the current stable distribution (woody) this problem has been
fixed in version 0.0.5-6woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-509');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-509
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA509] DSA-509-1 gatos");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-509-1 gatos");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gatos', release: '3.0', reference: '0.0.5-6woody1');
deb_check(prefix: 'libgatos-dev', release: '3.0', reference: '0.0.5-6woody1');
deb_check(prefix: 'libgatos0', release: '3.0', reference: '0.0.5-6woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
