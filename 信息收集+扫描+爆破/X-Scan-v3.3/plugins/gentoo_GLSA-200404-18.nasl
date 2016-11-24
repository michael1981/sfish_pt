# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(14483);
 script_version("$Revision: 1.9 $");
 script_xref(name: "GLSA", value: "200404-18");
 script_cve_id("CVE-2004-0156");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-18
(Multiple Vulnerabilities in ssmtp)


    There are two format string vulnerabilities inside the log_event() and
    die() functions of ssmtp. Strings from outside ssmtp are passed to various
    printf()-like functions from within log_event() and die() as format
    strings. An attacker could cause a specially-crafted string to be passed to
    these functions, and potentially cause ssmtp to execute arbitrary code.
  
Impact

    If ssmtp connects to a malicious mail relay server, this vulnerability can
    be used to execute code with the rights of the mail sender, including root.
  
Workaround

    There is no known workaround at this time. All users are advised to upgrade
    to the latest available version of ssmtp.
  
');
script_set_attribute(attribute:'solution', value: '
    All users are advised to upgrade to the latest available version of ssmtp.
    # emerge sync
    # emerge -pv ">=mail-mta/ssmtp-2.60.7"
    # emerge ">=mail-mta/ssmtp-2.60.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/11378/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0156');
script_set_attribute(attribute: 'see_also', value: 'http://lists.debian.org/debian-security-announce/debian-security-announce-2004/msg00084.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-18] Multiple Vulnerabilities in ssmtp');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple Vulnerabilities in ssmtp');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-mta/ssmtp", unaffected: make_list("ge 2.60.7"), vulnerable: make_list("le 2.60.4-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
