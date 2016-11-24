# This script was automatically generated from the dsa-422
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15259);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "422");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-422 security update');
 script_set_attribute(attribute: 'description', value:
'The account management of the CVS pserver (which is used to give remote
access to CVS repositories) uses a CVSROOT/passwd file in each
repository which contains the accounts and their authentication
information as well as the name of the local unix account to use when a
pserver account is used. Since CVS performed no checking on what unix
account was specified anyone who could modify the CVSROOT/passwd
could gain access to all local users on the CVS server, including root.
This has been fixed in upstream version 1.11.11 by preventing pserver
from running as root. For Debian this problem is solved in version
1.11.1p1debian-9 in two different ways:
Additionally, CVS pserver had a bug in parsing module requests which
could be used to create files and directories outside a repository.
This has been fixed upstream in version 1.11.11 and Debian version
1.11.1p1debian-9.
Finally, the umask used for &ldquo;cvs init&rdquo; and
&ldquo;cvs-makerepos&rdquo; has been
changed to prevent repositories from being created with group write
permissions.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-422');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-422
and install the recommended updated packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA422] DSA-422-1 cvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-422-1 cvs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-9');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
