# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200908-05.xml
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
 script_id(40630);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200908-05");
 script_cve_id("CVE-2009-2411");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200908-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200908-05
(Subversion: Remote execution of arbitrary code)


    Matt Lewis of Google reported multiple integer overflows in the
    libsvn_delta library, possibly leading to heap-based buffer overflows.
  
Impact

    A remote attacker with commit access could exploit this vulnerability
    by sending a specially crafted commit to a Subversion server, or a
    remote attacker could entice a user to check out or update a repository
    from a malicious Subversion server, possibly resulting in the execution
    of arbitrary code with the privileges of the user running the server or
    client.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Subversion users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =dev-util/subversion-1.6.4
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2411');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200908-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200908-05] Subversion: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Subversion: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/subversion", unaffected: make_list("ge 1.6.4"), vulnerable: make_list("lt 1.6.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
