# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-18.xml
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
 script_id(15693);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200411-18");
 script_cve_id("CVE-2004-0942");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-18
(Apache 2.0: Denial of Service by memory consumption)


    Chintan Trivedi discovered a vulnerability in Apache httpd 2.0 that is caused by improper enforcing of the field length limit in the header-parsing code.
  
Impact

    By sending a large amount of specially-crafted HTTP GET requests a remote attacker could cause a Denial of Service of the targeted system.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Apache 2.0 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/apache-2.0.52-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0942');
script_set_attribute(attribute: 'see_also', value: 'http://www.apacheweek.com/features/security-20');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-18] Apache 2.0: Denial of Service by memory consumption');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 2.0: Denial of Service by memory consumption');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("ge 2.0.52-r1", "lt 2.0"), vulnerable: make_list("lt 2.0.52-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
