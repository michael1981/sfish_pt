# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-05.xml
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
 script_id(31836);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200804-05");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-05
(NX: User-assisted execution of arbitrary code)


    Multiple integer overflow and buffer overflow vulnerabilities have been
    discovered in the X.Org X server as shipped by NX and NX Node
    (vulnerabilities 1-4 in GLSA 200801-09).
  
Impact

    A remote attacker could exploit these vulnerabilities via unspecified
    vectors, leading to the execution of arbitrary code with the privileges
    of the user on the machine running the NX server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All NX Node users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/nxnode-3.1.0-r2"
    All NX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/nx-3.1.0-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200801-09.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-05] NX: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'NX: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/nxnode", unaffected: make_list("ge 3.1.0-r2"), vulnerable: make_list("lt 3.1.0-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-misc/nx", unaffected: make_list("ge 3.1.0-r1"), vulnerable: make_list("lt 3.1.0-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
