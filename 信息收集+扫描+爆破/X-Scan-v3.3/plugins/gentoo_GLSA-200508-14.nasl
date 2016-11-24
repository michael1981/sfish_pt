# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-14.xml
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
 script_id(19534);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200508-14");
 script_cve_id("CVE-2005-2498");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200508-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200508-14
(TikiWiki, eGroupWare: Arbitrary command execution through XML-RPC)


    The XML-RPC library shipped in TikiWiki and eGroupWare improperly
    handles XML-RPC requests and responses with malformed nested tags.
  
Impact

    A remote attacker could exploit this vulnerability to inject
    arbitrary PHP script code into eval() statements by sending a specially
    crafted XML document to TikiWiki or eGroupWare.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All TikiWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/tikiwiki-1.8.5-r2"
    All eGroupWare users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/egroupware-1.0.0.009"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2498');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200508-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200508-14] TikiWiki, eGroupWare: Arbitrary command execution through XML-RPC');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'TikiWiki, eGroupWare: Arbitrary command execution through XML-RPC');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/egroupware", unaffected: make_list("ge 1.0.0.009"), vulnerable: make_list("lt 1.0.0.009")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/tikiwiki", unaffected: make_list("ge 1.8.5-r2"), vulnerable: make_list("lt 1.8.5-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
