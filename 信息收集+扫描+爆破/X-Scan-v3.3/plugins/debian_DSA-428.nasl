# This script was automatically generated from the dsa-428
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15265);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "428");
 script_cve_id("CVE-2003-0848");
 script_bugtraq_id(8780);
 script_xref(name: "CERT", value: "441956");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-428 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability was discovered in slocate, a program to index and
search for files, whereby a specially crafted database could overflow
a heap-based buffer.  This vulnerability could be exploited by a local
attacker to gain the privileges of the "slocate" group, which can
access the global database containing a list of pathnames of all files
on the system, including those which should only be visible to
privileged users.
This problem, and a category of potential similar problems, have been
fixed by modifying slocate to drop privileges before reading a
user-supplied database.
For the current stable distribution (woody) this problem has been
fixed in version 2.6-1.3.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-428');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-428
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA428] DSA-428-1 slocate");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-428-1 slocate");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'slocate', release: '3.0', reference: '2.6-1.3.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
