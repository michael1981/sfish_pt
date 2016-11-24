# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-27.xml
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
 script_id(17588);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200503-27");
 script_cve_id("CVE-2005-0830");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-27 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-27
(Xzabite dyndnsupdate: Multiple vulnerabilities)


    Toby Dickenson discovered that dyndnsupdate suffers from multiple
    overflows.
  
Impact

    A remote attacker, posing as a dyndns.org server, could execute
    arbitrary code with the rights of the user running dyndnsupdate.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    Currently, there is no released version of dyndnsupdate that contains a
    fix for these issues. The original xzabite.org distribution site is
    dead, the code contains several other problems and more secure
    alternatives exist, such as the net-dns/ddclient package. Therefore,
    the dyndnsupdate package has been hard-masked prior to complete removal
    from Portage, and current users are advised to unmerge the package:
    # emerge --unmerge net-misc/dyndnsupdate
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0830');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-27.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-27] Xzabite dyndnsupdate: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xzabite dyndnsupdate: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/dyndnsupdate", unaffected: make_list(), vulnerable: make_list("le 0.6.15")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
