# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-03.xml
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
 script_id(14536);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200407-03");
 script_cve_id("CVE-2004-0493");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-03
(Apache 2: Remote denial of service attack)


    A bug in the protocol.c file handling header lines will cause Apache to
    allocate memory for header lines starting with TAB or SPACE.
  
Impact

    An attacker can exploit this vulnerability to perform a Denial of Service
    attack by causing Apache to exhaust all memory. On 64 bit systems with more
    than 4GB of virtual memory a possible integer signedness error could lead
    to a buffer based overflow causing Apache to crash and under some
    circumstances execute arbitrary code as the user running Apache, usually
    "apache".
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version:
  
');
script_set_attribute(attribute:'solution', value: '
    Apache 2 users should upgrade to the latest version of Apache:
    # emerge sync
    # emerge -pv ">=www-servers/apache-2.0.49-r4"
    # emerge ">=www-servers/apache-2.0.49-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.guninski.com/httpd1.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0493');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-03] Apache 2: Remote denial of service attack');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 2: Remote denial of service attack');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("ge 2.0.49-r4", "lt 2"), vulnerable: make_list("le 2.0.49-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
