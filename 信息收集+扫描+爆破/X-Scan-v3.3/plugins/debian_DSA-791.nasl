# This script was automatically generated from the dsa-791
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19561);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "791");
 script_cve_id("CVE-2005-2655");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-791 security update');
 script_set_attribute(attribute: 'description', value:
'Max Vozeler discovered that the lockmail program from maildrop, a
simple mail delivery agent with filtering abilities, does not drop
group privileges before executing commands given on the commandline,
allowing an attacker to execute arbitrary commands with privileges of
the group mail.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 1.5.3-1.1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-791');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your maildrop package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA791] DSA-791-1 maildrop");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-791-1 maildrop");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'maildrop', release: '3.1', reference: '1.5.3-1.1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
