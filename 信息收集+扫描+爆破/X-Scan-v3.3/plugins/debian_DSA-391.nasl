# This script was automatically generated from the dsa-391
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15228);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "391");
 script_cve_id("CVE-2003-0828");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-391 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp discovered a buffer overflow in freesweep, when processing
several environment variables.  This vulnerability could be exploited
by a local user to gain gid \'games\'.
For the current stable distribution (woody) this problem has been fixed
in version 0.88-4woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-391');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-391
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA391] DSA-391-1 freesweep");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-391-1 freesweep");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'freesweep', release: '3.0', reference: '0.88-4woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
