# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-02.xml
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
 script_id(18606);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200507-02");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-02
(WordPress: Multiple vulnerabilities)


    James Bercegay of the GulfTech Security Research Team discovered
    that WordPress insufficiently checks data passed to the XML-RPC server.
    He also discovered that WordPress has several cross-site scripting and
    full path disclosure vulnerabilities.
  
Impact

    An attacker could use the PHP script injection vulnerabilities to
    execute arbitrary PHP script commands. Furthermore the cross-site
    scripting vulnerabilities could be exploited to execute arbitrary
    script code in a user\'s browser session in context of a vulnerable
    site.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All WordPress users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/wordpress-1.5.1.3"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1921');
script_set_attribute(attribute: 'see_also', value: 'http://www.gulftech.org/?node=research&article_id=00085-06282005');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-02] WordPress: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'WordPress: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/wordpress", unaffected: make_list("ge 1.5.1.3"), vulnerable: make_list("lt 1.5.1.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
