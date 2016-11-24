# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200810-01.xml
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
 script_id(34365);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200810-01");
 script_cve_id("CVE-2008-2149", "CVE-2008-3908");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200810-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200810-01
(WordNet: Execution of arbitrary code)


    Jukka Ruohonen initially reported a boundary error within the
    searchwn() function in src/wn.c. A thorough investigation by the oCERT
    team revealed several other vulnerabilities in WordNet:
    Jukka Ruohonen and Rob Holland (oCERT) reported multiple boundary
    errors within the searchwn() function in src/wn.c, the wngrep()
    function in lib/search.c, the morphstr() and morphword() functions in
    lib/morph.c, and the getindex() in lib/search.c, which lead to
    stack-based buffer overflows.
    Rob Holland (oCERT) reported two
    boundary errors within the do_init() function in lib/morph.c, which
    lead to stack-based buffer overflows via specially crafted
    "WNSEARCHDIR" or "WNHOME" environment variables.
    Rob Holland
    (oCERT) reported multiple boundary errors in the bin_search() and
    bin_search_key() functions in binsrch.c, which lead to stack-based
    buffer overflows via specially crafted data files.
    Rob Holland
    (oCERT) reported a boundary error within the parse_index() function in
    lib/search.c, which leads to a heap-based buffer overflow via specially
    crafted data files.
  
Impact

    In case the application is accessible e.g. via a web server,
    a remote attacker could pass overly long strings as arguments to the
    "wm" binary, possibly leading to the execution of arbitrary code.
    A local attacker could exploit the second vulnerability via
    specially crafted "WNSEARCHDIR" or "WNHOME" environment variables,
    possibly leading to the execution of arbitrary code with escalated
    privileges.
    A local attacker could exploit the third and
    fourth vulnerability by making the application use specially crafted
    data files, possibly leading to the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All WordNet users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-dicts/wordnet-3.0-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2149');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3908');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200810-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200810-01] WordNet: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'WordNet: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-dicts/wordnet", unaffected: make_list("ge 3.0-r2"), vulnerable: make_list("lt 3.0-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
