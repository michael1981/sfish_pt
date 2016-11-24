# This script was automatically generated from the dsa-769
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19318);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "769");
 script_cve_id("CVE-2005-2370");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-769 security update');
 script_set_attribute(attribute: 'description', value:
'Szymon Zygmunt and Michal Bartoszkiewicz discovered a memory alignment
error in libgadu (from ekg, console Gadu Gadu client, an instant
messaging program) which is included in gaim, a multi-protocol instant
messaging client, as well.  This can not be exploited on the x86
architecture but on others, e.g. on Sparc and lead to a bus error,
in other words a denial of service.
The old stable distribution (woody) does not seem to be affected by
this problem.
For the stable distribution (sarge) this problem has been fixed in
version 1.2.1-1.4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-769');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gaim package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA769] DSA-769-1 gaim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-769-1 gaim");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gaim', release: '3.1', reference: '1.2.1-1.4');
deb_check(prefix: 'gaim-data', release: '3.1', reference: '1.2.1-1.4');
deb_check(prefix: 'gaim-dev', release: '3.1', reference: '1.2.1-1.4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
