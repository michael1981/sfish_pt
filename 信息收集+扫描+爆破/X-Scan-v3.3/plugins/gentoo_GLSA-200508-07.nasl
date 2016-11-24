# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-07.xml
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
 script_id(19440);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200508-07");
 script_cve_id("CVE-2005-1527");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200508-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200508-07
(AWStats: Arbitrary code execution using malicious Referrer information)


    When using a URLPlugin, AWStats fails to sanitize Referrer URL
    data before using them in a Perl eval() routine.
  
Impact

    A remote attacker can include arbitrary Referrer information in a
    HTTP request to a web server, therefore injecting tainted data in the
    log files. When AWStats is run on this log file, this can result in the
    execution of arbitrary Perl code with the rights of the user running
    AWStats.
  
Workaround

    Disable all URLPlugins in the AWStats configuration.
  
');
script_set_attribute(attribute:'solution', value: '
    All AWStats users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-misc/awstats-6.5"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1527');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=290&type=vulnerabilities');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200508-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200508-07] AWStats: Arbitrary code execution using malicious Referrer information');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AWStats: Arbitrary code execution using malicious Referrer information');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-misc/awstats", unaffected: make_list("ge 6.5"), vulnerable: make_list("lt 6.5")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
