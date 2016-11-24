# This script was automatically generated from the dsa-513
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15350);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "513");
 script_cve_id("CVE-2004-0450");
 script_bugtraq_id(10460);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-513 security update');
 script_set_attribute(attribute: 'description', value:
'jaguar@felinemenace.org discovered a format string vulnerability in
log2mail, whereby a user able to log a specially crafted message to a
logfile monitored by log2mail (for example, via syslog) could cause
arbitrary code to be executed with the privileges of the log2mail
process.  By default, this process runs as user \'log2mail\', which is a
member of group \'adm\' (which has access to read system logfiles).
CVE-2004-0450: log2mail format string vulnerability via syslog(3) in
printlog()
For the current stable distribution (woody), this problem has been
fixed in version 0.2.5.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-513');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-513
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA513] DSA-513-1 log2mail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-513-1 log2mail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'log2mail', release: '3.0', reference: '0.2.5.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
