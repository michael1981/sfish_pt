# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-16.xml
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
 script_id(16453);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200502-16");
 script_cve_id("CVE-2005-0085");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-16
(ht://Dig: Cross-site scripting vulnerability)


    Michael Krax discovered that ht://Dig fails to validate the
    \'config\' parameter before displaying an error message containing the
    parameter. This flaw could allow an attacker to conduct cross-site
    scripting attacks.
  
Impact

    By sending a carefully crafted message, an attacker can inject and
    execute script code in the victim\'s browser window. This allows to
    modify the behaviour of ht://Dig, and/or leak session information such
    as cookies to the attacker.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ht://Dig users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-misc/htdig-3.1.6-r7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0085');
script_set_attribute(attribute: 'see_also', value: 'http://securitytracker.com/alerts/2005/Feb/1013078.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-16] ht://Dig: Cross-site scripting vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ht://Dig: Cross-site scripting vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-misc/htdig", unaffected: make_list("ge 3.1.6-r7"), vulnerable: make_list("lt 3.1.6-r7")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
