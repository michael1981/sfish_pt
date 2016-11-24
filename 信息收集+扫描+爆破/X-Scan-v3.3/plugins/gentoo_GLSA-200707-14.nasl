# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200707-14.xml
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
 script_id(25810);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200707-14");
 script_cve_id("CVE-2007-3798");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200707-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200707-14
(tcpdump: Integer overflow)


    mu-b from Digital Labs discovered that the return value of a snprintf()
    call is not properly checked before being used. This could lead to an
    integer overflow.
  
Impact

    A remote attacker could send specially crafted BGP packets on a network
    being monitored with tcpdump, possibly resulting in the execution of
    arbitrary code with the privileges of the user running tcpdump, which
    is usually root.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All tcpdump users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/tcpdump-3.9.5-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3798');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200707-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200707-14] tcpdump: Integer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'tcpdump: Integer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/tcpdump", unaffected: make_list("ge 3.9.5-r3"), vulnerable: make_list("lt 3.9.5-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
