# This script was automatically generated from the dsa-309
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15146);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "309");
 script_cve_id("CVE-2003-0382");
 script_bugtraq_id(7708);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-309 security update');
 script_set_attribute(attribute: 'description', value:
'"bazarr" discovered that eterm is vulnerable to a buffer overflow of
the ETERMPATH environment variable.  This bug can be exploited to gain
the privileges of the group "utmp" on a system where eterm is
installed.
For the stable distribution (woody), this problem has been fixed in
version 0.9.2-0pre2002042903.1.
The old stable distribution (potato) is not affected by this bug.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-309');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-309
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA309] DSA-309-1 eterm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-309-1 eterm");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'eterm', release: '3.0', reference: '0.9.2-0pre2002042903.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
