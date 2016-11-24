# This script was automatically generated from the dsa-279
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15116);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "279");
 script_cve_id("CVE-2003-0202");
 script_bugtraq_id(7293);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-279 security update');
 script_set_attribute(attribute: 'description', value:
'Paul Szabo and Matt Zimmerman discovered two similar problems in
metrics, a tools for software metrics.  Two scripts in this package,
"halstead" and "gather_stats", open temporary files without taking
appropriate security precautions.  "halstead" is installed as a user
program, while "gather_stats" is only used in an auxiliary script
included in the source code.  These vulnerabilities could allow a
local attacker to overwrite files owned by the user running the
scripts, including root.
The stable distribution (woody) is not affected since it doesn\'t
contain a metrics package anymore.
For the old stable distribution (potato) this problem has been fixed
in version 1.0-1.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-279');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your metrics package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA279] DSA-279-1 metrics");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-279-1 metrics");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'metrics', release: '2.2', reference: '1.0-1.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
