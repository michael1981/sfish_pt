# This script was automatically generated from the dsa-384
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15221);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "384");
 script_cve_id("CVE-2003-0681", "CVE-2003-0694");
 script_bugtraq_id(8641, 8649);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-384 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities were reported in sendmail.
   A "potential buffer overflow in ruleset parsing" for Sendmail
   8.12.9, when using the nonstandard rulesets (1) recipient (2),
   final, or (3) mailer-specific envelope recipients, has unknown
   consequences.
  The prescan function in Sendmail 8.12.9 allows remote attackers to
  execute arbitrary code via buffer overflow attacks, as demonstrated
  using the parseaddr function in parseaddr.c.
For the stable distribution (woody) these problems have been fixed in
sendmail version 8.12.3-6.6 and sendmail-wide version
8.12.3+3.5Wbeta-5.5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-384');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-384
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA384] DSA-384-1 sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-384-1 sendmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmilter-dev', release: '3.0', reference: '8.12.3-6.6');
deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.3-6.6');
deb_check(prefix: 'sendmail-doc', release: '3.0', reference: '8.12.3-6.6');
deb_check(prefix: 'sendmail-wide', release: '3.0', reference: '8.12.3+3.5Wbeta-5.5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
