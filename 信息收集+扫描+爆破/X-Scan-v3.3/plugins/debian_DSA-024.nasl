# This script was automatically generated from the dsa-024
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14861);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "024");
 script_cve_id("CVE-2001-0235");
 script_bugtraq_id(2332);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-024 security update');
 script_set_attribute(attribute: 'description', value:
'The FreeBSD team has found a bug in the way new crontabs
were handled which allowed malicious users to display arbitrary crontab files
on the local system. This only affects valid crontab files so it can\'t be used to
get access to /etc/shadow or something. crontab files are not especially secure
anyway, as there are other ways they can leak. No passwords or similar
sensitive data should be in there. We recommend you upgrade your cron
packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-024');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-024
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA024] DSA-024-1 cron");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-024-1 cron");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cron', release: '2.2', reference: '3.0pl1-57.2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
