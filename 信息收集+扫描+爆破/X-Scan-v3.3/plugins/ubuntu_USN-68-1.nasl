# This script was automatically generated from the 68-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20688);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "68-1");
script_summary(english:"enscript vulnerabilities");
script_name(english:"USN68-1 : enscript vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "enscript" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Erik Sjölund discovered several vulnerabilities in enscript which
could cause arbitrary code execution with the privileges of the user
calling enscript.

Quotes and other shell escape characters in titles and file names were
not handled in previous versions. (CVE-2004-1184)

Previous versions supported reading EPS data not only from a file, but
also from an arbitrary command pipe. Since checking for unwanted side
effects is infeasible, this feature has been disabled after
consultation with the authors of enscript. (CVE-2004-1185)

Finally, this update fixes two buffer overflows which were triggered by
certain input files. (CVE-2004-1186)

These issues can lead to privilege escalation if enscript is called
automatically from web server applications like viewcvs.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- enscript-1.6.4-4ubuntu0.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2004-1184","CVE-2004-1185","CVE-2004-1186");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "enscript", pkgver: "1.6.4-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package enscript-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to enscript-1.6.4-4ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
