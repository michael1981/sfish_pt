# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-12.xml
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
 script_id(14498);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200405-12");
 script_cve_id("CVE-2004-0396");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-12
(CVS heap overflow vulnerability)


    Stefan Esser discovered a heap overflow in the CVS server, which can be
    triggered by sending malicious "Entry" lines and manipulating the flags
    related to that Entry. This vulnerability was proven to be exploitable.
  
Impact

    A remote attacker can execute arbitrary code on the CVS server, with the
    rights of the CVS server. By default, Gentoo uses the "cvs" user to run the
    CVS server. In particular, this flaw allows a complete compromise of CVS
    source repositories. If you\'re not running a server, then you are not
    vulnerable.
  
Workaround

    There is no known workaround at this time. All users are advised to upgrade
    to the latest available version of CVS.
  
');
script_set_attribute(attribute:'solution', value: '
    All users running a CVS server should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=dev-util/cvs-1.11.16"
    # emerge ">=dev-util/cvs-1.11.16"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://security.e-matters.de/advisories/072004.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0396');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-12] CVS heap overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CVS heap overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/cvs", unaffected: make_list("ge 1.11.16"), vulnerable: make_list("le 1.11.15")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
