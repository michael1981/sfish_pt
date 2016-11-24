# This script was automatically generated from the dsa-410
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15247);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "410");
 script_cve_id("CVE-2003-0850");
 script_bugtraq_id(8905);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-410 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability was discovered in libnids, a library used to analyze
IP network traffic, whereby a carefully crafted TCP datagram could
cause memory corruption and potentially execute arbitrary code with
the privileges of the user executing a program which uses libnids
(such as dsniff).
For the current stable distribution (woody) this problem has been
fixed in version 1.16-3woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-410');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-410
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA410] DSA-410-1 libnids");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-410-1 libnids");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libnids-dev', release: '3.0', reference: '1.16-3woody1');
deb_check(prefix: 'libnids1', release: '3.0', reference: '1.16-3woody1');
deb_check(prefix: 'libnids', release: '3.0', reference: '1.16-3woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
