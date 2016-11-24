# This script was automatically generated from the dsa-121
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14958);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "121");
 script_cve_id("CVE-2002-0332", "CVE-2002-0333", "CVE-2002-0334");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-121 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been found in the xtell
package, a simple messaging client and server.  In detail, these
problems contain several buffer overflows, a problem in connection
with symbolic links, unauthorized directory traversal when the path
contains "..".  These problems could lead into an attacker being able
to execute arbitrary code on the server machine.  The server runs with
nobody privileges by default, so this would be the account to be
exploited.
They have been corrected by backporting changes from a newer upstream
version by the Debian maintainer for xtell.  These problems are fixed
in version 1.91.1 in the stable distribution of Debian and in version
2.7 for the testing and unstable distribution of Debian.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-121');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xtell packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA121] DSA-121-1 xtell");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-121-1 xtell");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xtell', release: '2.2', reference: '1.91.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
