# This script was automatically generated from the dsa-447
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15284);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "447");
 script_cve_id("CVE-2004-0159");
 script_bugtraq_id(9715);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-447 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar from the Debian Security Audit Project
discovered a format string
vulnerability in hsftp.  This vulnerability could be exploited by an
attacker able to create files on a remote server with carefully
crafted names, to which a user would connect using hsftp.  When the
user requests a directory listing, particular bytes in memory could be
overwritten, potentially allowing arbitrary code to be executed with
the privileges of the user invoking hsftp.
Note that while hsftp is installed setuid root, it only uses these
privileges to acquire locked memory, and then relinquishes them.
For the current stable distribution (woody) this problem has been
fixed in version 1.11-1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-447');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-447
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA447] DSA-447-1 hsftp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-447-1 hsftp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'hsftp', release: '3.0', reference: '1.11-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
