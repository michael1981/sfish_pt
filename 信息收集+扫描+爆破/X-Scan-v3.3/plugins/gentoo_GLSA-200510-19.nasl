# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-19.xml
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
 script_id(20081);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200510-19");
 script_cve_id("CVE-2005-3185");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-19
(cURL: NTLM username stack overflow)


    iDEFENSE reported that insufficient bounds checking on a memcpy()
    of the supplied NTLM username can result in a stack overflow.
  
Impact

    A remote attacker could setup a malicious server and entice an
    user to connect to it using a cURL client, potentially leading to the
    execution of arbitrary code with the permissions of the user running
    cURL.
  
Workaround

    Disable NTLM authentication by not using the --anyauth or --ntlm
    options when using cURL (the command line version). Workarounds for
    programs that use the cURL library depend on the configuration options
    presented by those programs.
  
');
script_set_attribute(attribute:'solution', value: '
    All cURL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/curl-7.15.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3185');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=322&type=vulnerabilities');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-19] cURL: NTLM username stack overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'cURL: NTLM username stack overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/curl", unaffected: make_list("ge 7.15.0"), vulnerable: make_list("lt 7.15.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
