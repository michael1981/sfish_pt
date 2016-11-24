# This script was automatically generated from the dsa-1090
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22632);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1090");
 script_cve_id("CVE-2006-2447");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1090 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability has been discovered in SpamAssassin, a Perl-based spam
filter using text analysis, that can allow remote attackers to execute
arbitrary commands.  This problem only affects systems where spamd is
reachable via the internet and used with vpopmail virtual users, via
the "-v" / "--vpopmail" switch, and with the "-P" / "--paranoid"
switch which is not the default setting on Debian.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 3.0.3-2sarge1.
For the volatile archive for the stable distribution (sarge) this
problem has been fixed in version 3.1.0a-0volatile3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1090');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your spamd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1090] DSA-1090-1 spamassassin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1090-1 spamassassin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'spamassassin', release: '3.1', reference: '3.0.3-2sarge1');
deb_check(prefix: 'spamc', release: '3.1', reference: '3.0.3-2sarge1');
deb_check(prefix: 'spamassassin', release: '3.1', reference: '3.1.0a-0volatile3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
