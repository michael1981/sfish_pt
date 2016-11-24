# This script was automatically generated from the dsa-704
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18009);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "704");
 script_cve_id("CVE-2005-0387", "CVE-2005-0388");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-704 security update');
 script_set_attribute(attribute: 'description', value:
'Jens Steube discovered several vulnerabilities in remstats, the remote
statistics system.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    When processing uptime data on the unix-server a temporary file is
    opened in an insecure fashion which could be used for a symlink
    attack to create or overwrite arbitrary files with the permissions
    of the remstats user.
    The remoteping service can be exploited to execute arbitrary
    commands due to missing input sanitising.
For the stable distribution (woody) these problems have been fixed in
version 1.00a4-8woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-704');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your remstats packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA704] DSA-704-1 remstats");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-704-1 remstats");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'remstats', release: '3.0', reference: '1.00a4-8woody1');
deb_check(prefix: 'remstats-bintools', release: '3.0', reference: '1.00a4-8woody1');
deb_check(prefix: 'remstats-doc', release: '3.0', reference: '1.00a4-8woody1');
deb_check(prefix: 'remstats-servers', release: '3.0', reference: '1.00a4-8woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
