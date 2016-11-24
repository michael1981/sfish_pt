# This script was automatically generated from the dsa-056
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14893);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "056");
 script_cve_id("CVE-2001-1331");
 script_bugtraq_id(2720);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-056 security update');
 script_set_attribute(attribute: 'description', value:
'Ethan Benson found a bug in man-db packages as distributed in
Debian GNU/Linux 2.2. man-db includes a mandb tool which is used to
build an index of the manual pages installed on a system. When the -u or
-c option were given on the command-line to tell it to write its database
to a different location it failed to properly drop privileges before
creating a temporary file. This makes it possible for an attacker to do
a standard symlink attack to trick mandb into overwriting any file that
is writable by uid man, which includes the man and mandb binaries.

This has been fixed in version 2.3.16-3, and we recommend that you
upgrade your man-db package immediately. If you use suidmanager
you can also use that to make sure man and mandb are not installed
suid which protects you from this problem. This can be done with the
following commands:


  suidregister /usr/lib/man-db/man root root 0755
  suidregister /usr/lib/man-db/mandb root root 0755


Of course even when using suidmanager an upgrade is still strongly
recommended.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-056');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-056
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA056] DSA-056-1 man-db");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-056-1 man-db");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'man-db', release: '2.2', reference: '2.3.16-3');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
